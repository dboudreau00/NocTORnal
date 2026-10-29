"""Collection over HTTP: sources, polls, persona health and egress separation.

Nothing here loops: `run_once` polls one source once and no route starts a scheduler (decisions
30 and 46). No route returns a persona secret (invariant 7). Every route passes the caller's
ceiling (`user_ceiling(...)[0].name`) to the service, never None (the unfiltered worker path):
listings filter by it, and one source above it gets the 404 of a missing id. `/sources/{id}/run`
refuses with 409 while a BLOCKING readiness check fails, as `scripts/collection_poll.py` does per
pass, and responses that could lead a persona to a forum carry the docs/16 L3 notice.
"""
from __future__ import annotations

from datetime import timedelta
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.collection import (
    _SOURCE_VISIBLE_HELD,
    PERSONA_VISIBLE_SQL,
    SOURCE_KINDS,
    WATCH_TARGET_KINDS,
    WATCH_TELEGRAM_CHAT,
    Adapter,
    CollectionBusy,
    CollectionConflict,
    CollectionError,
    CollectionNotFound,
    CollectionService,
    PersonaResting,
    PersonaUnavailable,
    PersonaVault,
    SourceRefused,
    _attr,
    _held,
    active_window,
    default_adapters,
    header_text_problem,
)
from noctornal_api.collection_authority import (
    SOURCE_CEILING_ENV,
    AuthorityError,
    source_ceiling,
)
from noctornal_api import forum_adapters
from noctornal_api import telegram_service
from noctornal_api.db import SystemPurpose, system_connection
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_global,
    get_conn,
    require,
    require_global,
    system_conn,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.readiness import blocking_failures
from noctornal_api.security.access import AccessResolutionError, evaluate
from noctornal_api.stores import PgAccessResolver

router = APIRouter(prefix="/collection", tags=["collection"])

#: A source's and a persona's administration writes on a system connection (0179): the request
#: role may only read the collection plane, so a statement injected into a request cannot add or
#: rebind a source, or create or restore a persona, past these gates and their audit rows.
_CONFIG = system_conn(SystemPurpose.CONFIGURATION)

#: Repeated on every route that can put a persona in front of a site, naming the legal-review item
#: by its register number (docs/00 decision 69).
L3_NOTICE = (
    "Legal review item L3 is still open: authority to read a forum or a "
    "chat, publicly or as a member, is decided per jurisdiction. This "
    "software refuses every forum and Telegram read that no confirmed "
    "authority covers, and records who declared and who confirmed it; it "
    "cannot confer the authority, and nothing in it posts, messages or "
    "purchases."
)


def get_adapters() -> dict[str, Adapter]:
    """The adapter registry for the routes, so an HTTP test can register a stub adapter through
    app.dependency_overrides instead of patching the module."""
    return default_adapters()


def _holds(conn: psycopg.Connection, user: CurrentUser, permission: str) -> bool:
    """Whether a global role of the caller carries `permission`, asked
    without an AUTHZ_DENIED row (a question on a listing is not an attempt)
    and without the step-up freshness, which the action itself asks for:
    this decides whether a button is drawn."""
    return conn.execute(
        """SELECT EXISTS (
               SELECT 1 FROM iam.user_role ur
                 JOIN iam.role_permission rp ON rp.role_key = ur.role_key
                 JOIN iam.app_user u ON u.id = ur.user_id
                WHERE ur.user_id = %s AND u.is_active
                  AND rp.permission_key = %s)""",
        (user.user_id, permission)).fetchone()[0]


def refuse_unready(conn: psycopg.Connection) -> None:
    """409 while any BLOCKING readiness check fails, naming them: one sentence for the run route
    and the attended persona acts, never a copy."""
    unsettled = blocking_failures(conn)
    if unsettled:
        raise Problem(
            409, "Conflict",
            "This deployment is not ready to collect. Blocking readiness "
            "checks failing: " + ", ".join(unsettled) + ". These are the "
            "ones an operator settles before real material enters the "
            "system, and a covert poll against a real target must not run "
            "while they are open; retrying will not close them. GET "
            "/admin/readiness (user.manage) carries the evidence and the "
            "action for each. " + L3_NOTICE)


@router.get("/sources/due", response_model=dict)
def due_sources(
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """What is ready to poll. Reports; does not act.

    A new source is due at once, not after a full interval, or it looks broken to whoever just
    added it. Filtered by the caller's own ceiling: a source's name and URL are what its label
    protects.
    """
    clearance, keys = user_ceiling(conn, user.user_id)
    svc = CollectionService(conn, adapters)
    due = svc.due_sources(clearance=clearance.name, compartments=keys)
    # What waits on a person, by reason. A held source is not polled, not rescheduled and not a
    # failure.
    held = [{**h, "id": str(h["id"])}
            for h in svc.held_sources(clearance=clearance.name, compartments=keys)]
    # A due Telegram chat names its chat and exit.
    due = telegram_service.attach_due_facts(conn, due)
    return {"due": [{**d, "id": str(d["id"])} for d in due],
            "count": len(due),
            "refused": [h for h in held if h["reason"] == "REFUSED"],
            "waiting_on_persona": [h for h in held if h["reason"] == "PERSONA"],
            "awaiting_authority": [h for h in held if h["reason"] == "AUTHORITY"],
            "run": _run_readiness(conn, user),
            "notice": ("Nothing polls itself. Call /sources/{id}/run to "
                       "poll one source once. " + L3_NOTICE)}


#: The four blocking readiness checks in words, for the Feeds pane's Poll
#: now. The keys are `readiness.BLOCKING_CHECKS`; a key missing here is
#: shown as itself rather than dropped, so a fifth check added there still
#: disables the button.
_BLOCKING_WORDS = {
    "prohibited_content_policy":
        "no prohibited-content policy or escalation contact is recorded",
    "sample_origin_configured": "no sample origin is configured",
    "retention_rules_confirmed":
        "retention periods are still on their seeded placeholders",
    "security_officer_present": "no security officer account exists",
}


def _run_readiness(conn: psycopg.Connection, user: CurrentUser) -> dict:
    """Whether this caller's Poll now would be refused, and why, before they press it.

    `allowed` is `collection.run`, asked of the gate without writing an AUTHZ_DENIED row (a
    question on a listing is not an attempt). The blocking checks are named only to a caller who
    holds it, as they are the refusal that caller would get. The poll route still decides; this
    is the button's state.
    """
    try:
        ctx = PgAccessResolver(conn).resolve_global(
            user_id=user.user_id, permission_key="collection.run",
            object_classification="CLEAR", object_compartments=frozenset(),
            mfa_satisfied_at=user.session_mfa_at)
        allowed = evaluate(ctx).allowed
    except AccessResolutionError:
        allowed = False
    if not allowed:
        return {"allowed": False, "ready": None, "blocking": []}
    failing = blocking_failures(conn)
    return {"allowed": True, "ready": not failing,
            "blocking": [{"check": name,
                          "text": _BLOCKING_WORDS.get(name, name)}
                         for name in failing]}


@router.get("/sources/unhealthy", response_model=dict)
def unhealthy(
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Sources whose parser has stopped matching.

    A parser fails by returning zero items rather than raising, usually because the site changed
    its markup, so this list is how a quiet feed gets noticed. `never_polled` is reported apart: a
    source that has never run is not broken, and mixing it in pads the alert.
    """
    clearance, held = user_ceiling(conn, user.user_id)
    svc = CollectionService(conn)
    # The reader's compartments too, or these lists would name a compartmented source to a reader
    # without the key.
    rows = svc.unhealthy_sources(clearance=clearance.name, compartments=held)
    never = svc.never_polled_sources(clearance=clearance.name,
                                     compartments=held)
    return {"sources": rows, "count": len(rows),
            "never_polled": never, "never_polled_count": len(never),
            "notice": ("Never-polled sources are listed separately: added "
                       "and never collected from is worth knowing, and it is "
                       "not the same thing as broken.")}


class RunBody(BaseModel):
    persona_id: UUID | None = None
    watch_id: UUID | None = None


@router.post("/sources/{source_id}/run", response_model=dict,
             dependencies=[Depends(rate_limit("capture"))])
def run_once(
    source_id: UUID, body: RunBody,
    user: CurrentUser = Depends(require_global("collection.run")),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """Poll one source, once.

    Every outcome, failures included, becomes a `collection_run` row, and the poll writes documents
    and watch hits, never `collect.proposal`. Metered under `capture`. 404 for a source above the
    caller's ceiling, as for a missing one, since the SSRF guard names the host in `error`. 409
    while a BLOCKING readiness check fails (pointing to `GET /admin/readiness`), for an unusable
    persona, and for a source another runner is polling; only the last is worth retrying at once.
    """
    # Before the ceiling lookup: a fact about the deployment, not the caller or the source, and the
    # same answer for every source id, so it is no oracle to a holder of global `collection.run`.
    refuse_unready(conn)
    clearance, held = user_ceiling(conn, user.user_id)
    # A source a persona reads is polled by the collector, the one process holding the persona key,
    # so this route queues it as a persona act and answers with its outcome (or 202 while queued).
    # A feed no persona reads polls here. A source above the caller, or under a compartment they do
    # not hold, is the same 404 either way.
    persona_read = _persona_read_label(conn, source_id, clearance.name, adapters,
                                       held)
    if persona_read is not None:
        from noctornal_api.http.routers.collection_acts import act_answer
        return act_answer(
            conn, user, kind="SOURCE_POLL", source_id=source_id,
            classification=persona_read, adapters=adapters, factory=None,
            params={"persona_id": body.persona_id, "watch_id": body.watch_id})
    try:
        # The poll runs on a system connection, as the cron's does: a new item dedupes against
        # every stored version and is matched against every case's watches, which a run seeing only
        # its caller's documents would get wrong. The caller's ceiling still decides whether the
        # source may be run at all (run_once's 404 below).
        with system_connection(SystemPurpose.COLLECTION, reuse=conn) as sconn:
            result = CollectionService(sconn, adapters).run_once(
                source_id, actor_id=user.user_id, persona_id=body.persona_id,
                watch_id=body.watch_id, clearance=clearance.name,
                compartments=held)
    except CollectionError as exc:
        raise run_problem(exc) from exc
    return run_body(result)


def _persona_read_label(conn: psycopg.Connection, source_id: UUID,
                        clearance: str, adapters: dict,
                        compartments=None) -> str | None:
    """The source's label when a persona reads it (its adapter names a
    persona platform), else None. A source above the caller, outside their
    compartments, or none at all, is the run route's 404 as ever."""
    from noctornal_api.collection import _source_row

    try:
        source = _source_row(conn, source_id, clearance, compartments)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    adapter = adapters.get(source.parser_key)
    if adapter is None or _attr(adapter, "persona_platform") is None:
        return None
    return source.classification


def run_problem(exc: CollectionError) -> Problem:
    """The run route's answer for a refused or failed poll, whether it ran here or in the
    collector. A subclass is tested before its parent."""
    if isinstance(exc, (SourceRefused, PersonaResting, AuthorityError)):
        # Before the CollectionError fallback, as CollectionBusy is: each means "you are allowed,
        # this cannot run", and nothing was done, so 409 rather than a 400 that blames the request.
        return Problem(409, "Conflict", safe_detail(exc))
    if isinstance(exc, PersonaUnavailable):
        # 409 rather than 403: the caller is allowed, the persona is not
        # usable: suspended, burnt, or cooling down.
        return Problem(409, "Conflict", safe_detail(exc))
    if isinstance(exc, CollectionBusy):
        # Before the CollectionError fallback, which would catch this subclass as a 400: the poll
        # is already running (a double-click, or the scheduled poll), and retrying is right.
        return Problem(409, "Conflict", safe_detail(exc))
    if isinstance(exc, CollectionNotFound):
        return Problem(404, "Not found", safe_detail(exc))
    return Problem(400, "Invalid request", safe_detail(exc))


def run_body(result) -> dict:
    """What a finished poll answers, here and from the collector."""
    return {
        "run_id": str(result.run_id),
        "items_seen": result.items_seen,
        "items_new": result.items_new,
        "watch_hits": result.watch_hits,
        "error": result.error,
        # BLOCKED and RATE_LIMITED are not failures, and a note (a walk that stopped at its budget)
        # is not a warning.
        "status": result.status,
        "blocked_reason": result.blocked_reason,
        "items_deleted": result.items_deleted,
        "notes": result.notes,
        # What the run could not do while otherwise succeeding: a watch whose regex does not
        # compile matches nothing, and would otherwise look like one that has not fired.
        "warnings": result.warnings,
        "notice": L3_NOTICE,
    }


@router.get("/personas", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def personas(
    user: CurrentUser = Depends(require_global("collection_account.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Persona health: whether each persona is usable and why not. Never a secret (invariant 7).

    Each row names the persona's source, so the list is filtered by the caller's ceiling against
    the source's label (`PersonaVault.personas` says how).
    """
    clearance, held = user_ceiling(conn, user.user_id)
    personas = PersonaVault(conn).personas(clearance=clearance.name,
                                           compartments=held)
    # A Telegram persona row carries its enrolment, hold and chat count; never a secret column.
    personas = telegram_service.attach_persona_facts(
        conn, personas, clearance.name, held)
    return {
        "personas": personas,
        "notice": ("Secrets are never returned by any endpoint. " + L3_NOTICE),
    }


class PersonaStatusBody(BaseModel):
    status: str
    reason: str = Field(min_length=5)
    #: A COOLDOWN says how long: one with no end was usable to one
    #: reader and resting to another.
    cooldown_hours: int | None = Field(default=None, ge=1, le=24 * 90)


#: The persona statuses that STOP it: a forum persona holds no session past one.
_STOPS = ("LOCKED", "BURNED")


def _sign_out_forum(conn: psycopg.Connection, persona_id: UUID, user: CurrentUser,
                    clearance: str, held, adapters: dict) -> str | None:
    """Sign a forum persona out of its boards before it is stopped; None for any other persona and
    for one with no session, else a sentence on what was and was not reached.

    Only the collector can open the sealed session (decision 174), so this asks it for a STOP act
    (`FORUM_SIGN_OUT`) and waits a bounded time; development's inline mode runs it here. A courtesy
    that may not be reached: the stop goes on regardless and `PersonaVault` clears the sealed
    session in the same call. Never raises into the stop; a persona the caller cannot see is left
    for `set_status` to answer 404."""
    from noctornal_api import persona_acts

    row = conn.execute(
        f"""SELECT a.platform::text, a.session_sealed_at IS NOT NULL,
                   coalesce((SELECT max(s.classification)
                               FROM collect.source s
                              WHERE s.collection_account_id = a.id
                                 OR s.id = a.source_id),
                            %(clearance)s::core.tlp)::text
              FROM collect.collection_account a
             WHERE a.id = %(id)s AND {PERSONA_VISIBLE_SQL}""",
        {"id": persona_id, "clearance": clearance,
         "held": _held(held)}).fetchone()
    if row is None or row[0] not in ("XENFORO", "MYBB") or not row[1]:
        return None
    unreached = ("The forum's own sign-out was not reached; the session this "
                 "product held was cleared by the stop.")
    try:
        act = persona_acts.submit(
            conn, user_id=user.user_id, session_id=user.session_id,
            mfa_at=user.session_mfa_at, kind="FORUM_SIGN_OUT",
            params={"persona_id": str(persona_id)}, classification=row[2],
            source_id=None)
        if persona_acts.inline_mode():
            act, body = persona_acts.run_inline(conn, act, adapters=adapters)
        else:
            act = persona_acts.wait(conn, act["id"], user_id=user.user_id,
                                    seconds=persona_acts.wait_seconds())
            body = ((act.get("result") or {}).get("body")
                    if act and act["status"] == "DONE" else None)
            if act and act["status"] in persona_acts.LIVE:
                # The collector has not started it: the stop clears the
                # session now, so there is nothing left for the act to do.
                persona_acts.cancel(conn, act["id"], user_id=user.user_id,
                                    clearance=clearance)
    except Exception:  # noqa: BLE001 - a stop is always allowed
        import logging
        logging.getLogger("noctornal.collection").warning(
            "the forum sign-out of persona %s failed; the stop goes on",
            persona_id, exc_info=True)
        return unreached
    if body and any(s.get("reached") for s in body.get("signed_out", [])):
        return "The persona was signed out of its forum, and its session cleared."
    return unreached


@router.post("/personas/{persona_id}/status", response_model=dict)
def set_persona_status(
    persona_id: UUID, body: PersonaStatusBody,
    user: CurrentUser = Depends(require_global("collection_account.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    sconn: psycopg.Connection = Depends(_CONFIG),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """Suspend or restore a persona, with the reason a later operator reads before reusing it.

    404 for a persona whose source is above the caller's ceiling, as for a missing one, so an
    over-ceiling caller cannot change a persona the list hides from them.
    """
    clearance, held = user_ceiling(conn, user.user_id)
    cooldown = (timedelta(hours=body.cooldown_hours)
                if body.cooldown_hours else None)
    # A STOP of a forum persona signs it out of its boards first, as a persona act the collector
    # runs. The sign-out is a courtesy that may not be reached; the guarantee is `PersonaVault`
    # clearing what this product holds sealed, on every stop.
    signed_out = (_sign_out_forum(conn, persona_id, user, clearance.name, held,
                                  adapters)
                  if body.status in _STOPS else None)
    try:
        written = PersonaVault(sconn).set_status(
            persona_id, body.status, actor_id=user.user_id,
            reason=body.reason, cooldown=cooldown, clearance=clearance.name,
            compartments=held)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    answer = {"persona_id": str(persona_id), "status": body.status}
    if signed_out:
        answer["forum_sign_out"] = signed_out
    # HEALTHY under a platform's hold or lock changes the person's status only, and the answer says
    # the persona stays paused.
    if written.get("notice"):
        answer["notice"] = written["notice"]
    return answer


@router.get("/sources/{source_id}/egress", response_model=dict)
def egress_separation(
    source_id: UUID,
    user: CurrentUser = Depends(require_global("collection_account.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Personas that would share an egress path against one source.

    Two personas reaching one forum from one address is the cheapest correlation an observer gets,
    and invisible from inside either persona. 404 for a source above the caller's ceiling, as for a
    missing one, since an empty answer would report "clean" about a forum they may not know exists.
    """
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        findings = PersonaVault(conn).check_egress_separation(
            source_id, clearance=clearance.name, compartments=held)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    return {"source_id": str(source_id), "findings": findings,
            "count": len(findings),
            "notice": ("An empty result means no SHARED egress was found "
                       "among the personas configured for this source. It "
                       "is not an assurance that the egress is safe.")}


@router.get("/runs", response_model=dict)
def runs(
    source_id: UUID | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Recent polls, successes and failures alike.

    A run that fetched 200 items and parsed none is a broken parser, which only a recorded run
    tells apart from a quiet feed. Filtered by the caller's ceiling against the source's label.
    """
    clearance, held = user_ceiling(conn, user.user_id)
    rows = CollectionService(conn).runs(
        source_id=source_id, limit=limit, clearance=clearance.name,
        compartments=held)
    return {"runs": rows, "count": len(rows),
            "note": ("A run with items_seen > 0 and items_new = 0 across "
                     "several polls is usually a parser that stopped "
                     "matching, not a quiet source.")}


# ---------------------------------------------------------------------------
# The read path: what the collector collected
# ---------------------------------------------------------------------------

@router.get("/documents", response_model=dict)
def documents(
    source_id: UUID | None = Query(default=None),
    triage_state: str | None = Query(default=None),
    limit: int = Query(100, ge=1, le=500),
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Collected documents, newest first.

    Not case-scoped: a document hangs off a source and may be evidence in many cases. Gated on the
    global `collection.read` and filtered by classification, which defaults to AMBER.
    """
    # The reader's compartments too: a capture into a compartmented case is stored under its keys.
    clearance, held = user_ceiling(conn, user.user_id)
    # Document holds (docs/00 decision 74): placing one needs retention.manage as well as the
    # collection.read above, and only such a caller reads a hold's reason.
    can_hold = _holds(conn, user, "retention.manage")
    docs = CollectionService(conn).documents(
        clearance=clearance.name, compartments=held, source_id=source_id,
        triage_state=triage_state, limit=limit, with_hold_reason=can_hold)
    # A Telegram document carries its capture record.
    docs = telegram_service.attach_message_meta(conn, docs)
    return {"documents": docs, "count": len(docs),
            "can_hold": can_hold,
            "note": ("Bodies are excerpted to 400 characters; `truncated` "
                     "says which. Purged documents are omitted entirely "
                     "rather than returned with an empty body.")}


# What a forum post or member carries beside its text (the signature, the posts it quotes, its
# reactions; a member's profile), read under the document's and its source's labels and its
# compartments, as the list reads the document. A document the caller may not see, or one with no
# forum details, is the same 404 a random id gets.
@router.get("/documents/{document_id}/forum", response_model=dict)
def forum_details(
    document_id: UUID,
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        return forum_adapters.forum_details(conn, document_id,
                                            clearance=clearance.name,
                                            compartments=held)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc


class TriageBody(BaseModel):
    state: str


@router.post("/documents/{document_id}/triage", response_model=dict)
def triage_document(
    document_id: UUID, body: TriageBody,
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Move a document between the four triage states the pane filters on.

    Gated as reading documents is, because triage is the reader's verb: global `collection.read`,
    and the document's classification against the caller's ceiling inside the service's UPDATE.
    A state outside the four is a 400 with the list; a document the caller cannot see is a 404.
    """
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        return CollectionService(conn).set_document_triage(
            document_id, body.state, actor_id=user.user_id,
            clearance=clearance.name, compartments=held)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc


case_router = APIRouter(prefix="/cases/{case_id}/collection",
                        tags=["collection"])


@case_router.get("/watch-hits", response_model=dict)
def watch_hits(
    case_id: UUID,
    unacknowledged_only: bool = Query(default=False),
    limit: int = Query(100, ge=1, le=500),
    user: CurrentUser = Depends(require("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """What the watches on this case matched.

    Case-scoped, because `collect.watch` carries `case_id` though the document does not.
    Suppressed hits are included with their reason, or a watch drowning in one recurring thread
    would look like a quiet one.
    """
    clearance, held = user_ceiling(conn, user.user_id)
    hits = CollectionService(conn).watch_hits(
        case_id, clearance=clearance.name, compartments=held,
        unacknowledged_only=unacknowledged_only, limit=limit)
    return {"hits": hits, "count": len(hits),
            "unacknowledged": sum(1 for h in hits if not h["acknowledged_at"]),
            "note": ("Unacknowledged first, then by score. A suppressed hit "
                     "is shown with its reason: alert hygiene is not the "
                     "same as nothing happening.")}


# No dedicated rate limit: this is an idempotent single-row UPDATE behind a
# case-scoped permission, and inventing a LIMITS key for it would add a
# meter nobody tuned. The global request limiter still applies.
@case_router.post("/watch-hits/{hit_id}/acknowledge", response_model=dict)
def acknowledge_watch_hit(
    case_id: UUID,
    hit_id: UUID,
    user: CurrentUser = Depends(require("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Record that somebody looked at this hit.

    Idempotent and it does not re-stamp: `acknowledged_at` is set once,
    because rewriting when somebody FIRST saw a hit destroys the only
    evidence of how long it sat unread.
    """
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        result = CollectionService(conn).acknowledge_hit(
            hit_id, user_id=user.user_id, clearance=clearance.name,
            compartments=held)
    except CollectionError as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    return result


class SuppressBody(BaseModel):
    #: No `min_length` here: the floor is the service's (`MIN_SUPPRESS_REASON_LENGTH`), so every
    #: caller meets the same rule and a short reason is a 400 in the service's words, not a 422.
    reason: str


@case_router.post("/watch-hits/{hit_id}/suppress", response_model=dict)
def suppress_watch_hit(
    case_id: UUID,
    hit_id: UUID, body: SuppressBody,
    user: CurrentUser = Depends(require("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Take a hit out of the queue, with a reason the list will show.

    The case in the path is handed to the service and must be the case
    the hit's watch belongs to: the gate above authorised the caller
    against THIS case, and a hit id from another case would otherwise be
    written under an authorisation that never covered it. A hit that is
    not on this case and a hit that does not exist get the same 404.
    """
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        return CollectionService(conn).suppress_hit(
            case_id, hit_id, actor_id=user.user_id, reason=body.reason,
            clearance=clearance.name, compartments=held)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc


@case_router.post("/watch-hits/{hit_id}/unsuppress", response_model=dict)
def unsuppress_watch_hit(
    case_id: UUID,
    hit_id: UUID,
    user: CurrentUser = Depends(require("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Put a hit back in the queue. Same gate, same case check, and the
    reason is cleared with it."""
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        return CollectionService(conn).unsuppress_hit(
            case_id, hit_id, actor_id=user.user_id, clearance=clearance.name,
            compartments=held)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc


# ---------------------------------------------------------------------------
# Watches
# ---------------------------------------------------------------------------
#
# A watch is a standing tasking whose terms are the case's content, so the list is read behind
# `collection.read` on the case. Making one takes two gates: the global `watch.manage`, held only
# by the collection manager's role, and the five-part gate on this case, which refuses a closed
# one. The verb alone would let a manager task a case they are not on; the case alone would let
# any analyst point the collector at a source.

class WatchCreate(BaseModel):
    #: No length or range constraints here, as in `SuppressBody`: the limits are the service's
    #: (`WATCH_*` in collection.py), so every caller meets one rule and a refusal is a 400.
    source_id: UUID
    name: str
    target_kind: str
    target_ref: str
    keywords: list[str] = Field(default_factory=list)
    selectors: list[str] = Field(default_factory=list)
    regexes: list[str] = Field(default_factory=list)
    priority: int = 3
    suppress_window_s: int = 3600


@case_router.get("/watches", response_model=dict)
def list_watches(
    case_id: UUID,
    user: CurrentUser = Depends(require("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The watches on this case, and whether the caller may add one.

    A watch on a source above the caller's ceiling is not listed (hidden is
    missing). `sources` is what the add form offers, and is sent only to a
    caller who holds `watch.manage`: it is the sources they may see, which
    is what a watch may be put on."""
    clearance, held = user_ceiling(conn, user.user_id)
    service = CollectionService(conn)
    rows = service.watches(case_id, clearance=clearance.name, compartments=held)
    can_create = _holds(conn, user, "watch.manage")
    return {"watches": rows, "count": len(rows), "can_create": can_create,
            "kinds": list(WATCH_TARGET_KINDS),
            "sources": (service.watch_sources(clearance=clearance.name,
                                              compartments=held)
                        if can_create else [])}


def _watch_next(watch: dict) -> str:
    """What happens to a watch that was just made, in words: when it starts,
    and the two cases the analyst should hear before the first hit."""
    said = ["It applies from the next poll of its source, to what that poll "
            "reads. Documents already collected are not matched again, and "
            "its hits are listed for this case."]
    if not watch["source_active"]:
        said.append("Its source is paused, so nothing is read from it until "
                    "it is activated.")
    if (watch["target_kind"] == WATCH_TELEGRAM_CHAT and not watch["keywords"]
            and not watch["selectors"] and not watch["regexes"]):
        said.append("It has no keyword, selector or pattern, so it fires on "
                    "every message of that chat, thinned only by its repeat "
                    "window.")
    return " ".join(said)


@case_router.post("/watches", response_model=dict, status_code=201,
                  dependencies=[Depends(require_global("watch.manage")),
                                Depends(rate_limit("collection.config"))])
def create_watch(
    case_id: UUID,
    body: WatchCreate,
    user: CurrentUser = Depends(require("collection.read", content_write=True)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """A new watch on this case. The source must be one the caller can see
    (a 404 otherwise, as for an id that is not one); a Telegram chat watch
    must name the chat its source reads, by its typed id; a watch of any
    other kind must carry at least one term. A name the case already holds
    is a 409. Audited as WATCH_CREATED, with the counts of its terms and
    never the terms."""
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        watch = CollectionService(conn).create_watch(
            case_id, source_id=body.source_id, name=body.name,
            target_kind=body.target_kind, target_ref=body.target_ref,
            keywords=body.keywords, selectors=body.selectors,
            regexes=body.regexes, priority=body.priority,
            suppress_window_s=body.suppress_window_s, actor_id=user.user_id,
            clearance=clearance.name, compartments=held)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    except CollectionConflict as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {"watch": watch, "next": _watch_next(watch)}


# ---------------------------------------------------------------------------
# Sources, personas and bindings
# ---------------------------------------------------------------------------
#
# Add a source, create a persona with no credential (an operator enrols it on the server), say who
# reads a source and through which exit, and deactivate one: each gated, rate limited under
# `collection.config` and audited.

def _adapter_rows(adapters: dict) -> list[dict]:
    return [{"parser_key": key,
             "kinds": sorted(_attr(a, "source_kinds") or ()),
             "requires_authority": bool(_attr(a, "requires_authority")),
             "persona_platform": _attr(a, "persona_platform"),
             "persona_http": bool(_attr(a, "persona_http")),
             "run_seconds": float(_attr(a, "run_seconds")),
             "max_rps_cap": float(_attr(a, "max_rps_cap")),
             "min_interval_s": int(_attr(a, "min_interval_s"))}
            for key, a in sorted(adapters.items())]


@router.get("/sources", response_model=dict)
def list_sources(
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """Every source the caller may see, who reads it and through which
    exit, its authority state and the refusal it would meet; the parsers
    this build has; the declared ceilings; and whether the caller may add
    sources (`can_manage`) or change who reads one (`can_bind`)."""
    clearance, held = user_ceiling(conn, user.user_id)
    rows = CollectionService(conn, adapters).sources(clearance=clearance.name,
                                                     compartments=held)
    manage = _holds(conn, user, "source.manage")
    return {"sources": rows, "count": len(rows),
            "adapters": _adapter_rows(adapters),
            "ceilings": {kind: source_ceiling(kind)[0]
                         for kind in sorted(SOURCE_CEILING_ENV)},
            "kinds": list(SOURCE_KINDS),
            "can_manage": manage,
            "can_bind": manage and _holds(conn, user, "collection_account.manage"),
            # A forum read leaves from this server's own address (development, no proxy, the
            # override set): the Poll now confirmation says so.
            "forum_reads_direct": forum_adapters.reads_direct(),
            "notice": L3_NOTICE}


class SourceCreate(BaseModel):
    kind: str = Field(min_length=2, max_length=20)
    name: str = Field(min_length=3, max_length=200)
    base_url: str | None = Field(default=None, max_length=2048)
    parser_key: str = Field(min_length=1, max_length=64)
    classification: str = Field(min_length=3, max_length=20)
    default_reliability: str = Field(default="F", pattern="^[A-F]$")
    poll_interval_s: int = Field(default=900, ge=60, le=7 * 86400)
    jitter_pct: int = Field(default=25, ge=0, le=90)
    max_rps: float = Field(default=0.2, gt=0, le=10)
    parser_config: dict = Field(default_factory=dict)
    collection_account_id: UUID | None = None
    egress_profile_id: UUID | None = None
    #: The compartments the source and everything it collects are filed under; the creator must
    #: hold each.
    compartments: list[str] = Field(default_factory=list, max_length=32)


@router.post("/sources", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("collection.config"))])
def create_source(
    body: SourceCreate,
    user: CurrentUser = Depends(require_global("source.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    sconn: psycopg.Connection = Depends(_CONFIG),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """A new source. A binding (a persona, or an exit for a persona-less
    read) also needs collection_account.manage, which is step-up. A forum or
    Telegram source is created and then waits: nothing is read until its
    authority is recorded and confirmed by two people."""
    if body.collection_account_id is not None or body.egress_profile_id is not None:
        authorize_global(conn, user, "collection_account.manage")
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        source = CollectionService(sconn, adapters).create_source(
            kind=body.kind, name=body.name, base_url=body.base_url,
            parser_key=body.parser_key, classification=body.classification,
            default_reliability=body.default_reliability,
            poll_interval_s=body.poll_interval_s, jitter_pct=body.jitter_pct,
            max_rps=body.max_rps, parser_config=body.parser_config,
            collection_account_id=body.collection_account_id,
            egress_profile_id=body.egress_profile_id, actor_id=user.user_id,
            clearance=clearance.name, compartments=body.compartments,
            held_compartments=held)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {"source": source,
            "next": ("A collection manager records the authority that covers "
                     "this source, and a security officer confirms it, before "
                     "it is polled." if source["requires_authority"] else
                     "It is due now: the next pass of the collector polls it.")}


class ReasonBody(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


def _set_active(source_id: UUID, body: ReasonBody, user: CurrentUser,
                conn: psycopg.Connection, active: bool,
                sconn: psycopg.Connection) -> dict:
    # The holder's own compartments, or the key holder who created a compartmented source would
    # meet a 404 on the one control that stops it.
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        return CollectionService(sconn).set_source_active(
            source_id, active=active, reason=body.reason,
            actor_id=user.user_id, clearance=clearance.name,
            compartments=held)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc


@router.post("/sources/{source_id}/deactivate", response_model=dict,
             dependencies=[Depends(rate_limit("collection.config"))])
def deactivate_source(
    source_id: UUID, body: ReasonBody,
    user: CurrentUser = Depends(require_global("source.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    sconn: psycopg.Connection = Depends(_CONFIG),
) -> dict:
    """Stop reading a source, with a reason; 404 above the caller."""
    return _set_active(source_id, body, user, conn, False, sconn)


@router.post("/sources/{source_id}/activate", response_model=dict,
             dependencies=[Depends(rate_limit("collection.config"))])
def activate_source(
    source_id: UUID, body: ReasonBody,
    user: CurrentUser = Depends(require_global("source.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    sconn: psycopg.Connection = Depends(_CONFIG),
) -> dict:
    """Read a source again, with a reason; 404 above the caller."""
    return _set_active(source_id, body, user, conn, True, sconn)


@router.get("/runs/{run_id}", response_model=dict)
def run_detail(
    run_id: UUID,
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """One poll with its custody log of what it asked for, read under the
    SOURCE's label: 404 above it, as for an id that is not a run."""
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        return CollectionService(conn).run_detail(run_id,
                                                  clearance=clearance.name,
                                                  compartments=held)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc


#: What a new persona's answer says, on every creation: no credential moves
#: through a browser.
_NO_CREDENTIAL_NOTICE = (
    "No credential is stored yet. An operator enrols it on the server, never "
    "through this console, because a sign-in code and an account password "
    "must not pass through a browser. ")


class PersonaCreate(BaseModel):
    handle: str = Field(min_length=2, max_length=64)
    platform: str = Field(min_length=2, max_length=20)
    egress_profile_id: UUID
    fingerprint: dict = Field(default_factory=dict)
    venue_source_id: UUID | None = None
    notes: str | None = Field(default=None, max_length=2000)


def _fingerprint_problems(fingerprint: dict) -> list[str]:
    """The generic keys of a persona's recorded identity: printable ASCII
    on one line for the two header values, a UTC window, and at most
    4 KiB in all."""
    import json

    problems = []
    if len(json.dumps(fingerprint, default=str).encode("utf-8")) > 4096:
        problems.append("A persona's recorded identity is at most 4 KiB.")
    if "user_agent" in fingerprint:
        problem = header_text_problem("browser identity",
                                      fingerprint["user_agent"], low=1, high=400)
        if problem:
            problems.append(problem)
    if "accept_language" in fingerprint:
        problem = header_text_problem("language", fingerprint["accept_language"],
                                      low=2, high=64)
        if problem:
            problems.append(problem)
    if "active_window_utc" in fingerprint:
        try:
            window = active_window(fingerprint["active_window_utc"])
        except ValueError:
            window = None
        if window is None or window[0] == window[1]:
            problems.append("Active hours are HH:MM-HH:MM in UTC, and not empty.")
    return problems


@router.post("/personas", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("collection.config"))])
def create_persona(
    body: PersonaCreate,
    user: CurrentUser = Depends(require_global("collection_account.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    sconn: psycopg.Connection = Depends(_CONFIG),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """A persona with no credential, on one platform, through one exit that
    no other persona holds (docs/04: one persona, one egress profile). The
    platform must be one a parser in this build reads through."""
    reader = next((a for a in adapters.values()
                   if _attr(a, "persona_platform") == body.platform), None)
    if reader is None:
        raise Problem(400, "Invalid request",
                      f"No adapter in this build reads through a "
                      f"{body.platform} persona.")
    problems = (_fingerprint_problems(body.fingerprint)
                + list(_attr(reader, "validate_persona")(dict(body.fingerprint))))
    if problems:
        raise Problem(400, "Invalid request", " ".join(problems))
    clearance, held = user_ceiling(conn, user.user_id)
    if body.venue_source_id is not None and conn.execute(
            f"""SELECT 1 FROM collect.source s WHERE s.id = %(id)s
                  AND {_SOURCE_VISIBLE_HELD}""",
            {"id": body.venue_source_id, "clearance": clearance.name,
             "held": _held(held)}).fetchone() is None:
        raise Problem(404, "Not found", "no such source, or it is above your clearance")
    try:
        persona = PersonaVault(sconn).create(
            handle=body.handle, platform=body.platform,
            egress_profile_id=body.egress_profile_id,
            fingerprint=dict(body.fingerprint), notes=body.notes,
            venue_source_id=body.venue_source_id, owner_user_id=user.user_id,
            actor_id=user.user_id)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {"persona": persona, "notice": _NO_CREDENTIAL_NOTICE + L3_NOTICE}


@router.get("/egress-profiles", response_model=dict)
def egress_profiles(
    user: CurrentUser = Depends(require_global("collection_account.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """THE listing persona and source forms pick an exit from. Counts of
    what the caller may see, one boolean for the rest, never the sealed
    endpoint or its key id. `available` is false when any persona holds the
    profile: that one bit of presence is the accepted PRESENCE disclosure
    (docs/05)."""
    clearance, held = user_ceiling(conn, user.user_id)
    rows = PersonaVault(conn).egress_profiles(clearance=clearance.name,
                                              compartments=held)
    return {"egress_profiles": rows, "count": len(rows),
            "notice": ("One persona, one egress profile: two personas seen "
                       "from one exit can be linked by any competent site.")}


class BindingBody(BaseModel):
    collection_account_id: UUID | None = None
    egress_profile_id: UUID | None = None
    reason: str = Field(min_length=5, max_length=500)
    reset_cursor: bool = False


@router.post("/sources/{source_id}/binding", response_model=dict,
             dependencies=[Depends(require_global("source.manage")),
                           Depends(rate_limit("collection.config"))])
def bind_source(
    source_id: UUID, body: BindingBody,
    user: CurrentUser = Depends(require_global("collection_account.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    sconn: psycopg.Connection = Depends(_CONFIG),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """Who reads a source and through which exit. Needs both permissions,
    and collection_account.manage is step-up. The authority recorded for
    the old binding stops covering the source at once, and the answer says
    so."""
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        return CollectionService(sconn, adapters).bind_source(
            source_id, persona_id=body.collection_account_id,
            egress_profile_id=body.egress_profile_id, reason=body.reason,
            reset_cursor=body.reset_cursor, actor_id=user.user_id,
            clearance=clearance.name, compartments=held)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc


def persona_visible(conn: psycopg.Connection, persona_id: UUID,
                    clearance: str, compartments=None) -> bool:
    """For an attended act's route: whether the caller may see the
    persona (set_status's predicate, compartments included)."""
    return conn.execute(
        f"SELECT 1 FROM collect.collection_account a "
        f"WHERE a.id = %(id)s AND {PERSONA_VISIBLE_SQL}",
        {"id": persona_id, "clearance": clearance,
         "held": _held(compartments)}).fetchone() is not None
