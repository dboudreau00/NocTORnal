"""Phase 4 over HTTP: sources, polls, persona health and egress separation.

## Nothing here loops

`due_sources` reports what is ready; `run_once` polls exactly one source
once. There is deliberately no "start collecting" endpoint and no
scheduler behind these routes.

That seam is decisions 30 and 46, and the reasoning in `collection.py` is
worth repeating because an interface is exactly where it gets eroded: a
collector that runs itself on a timer nobody watches is how a persona gets
burnt at 3am. A scheduler is a legitimate thing to build -- it is on the
roadmap -- but it belongs in a worker whose failure is visible, not behind
a button that starts something nobody is watching.

## Invariant 7 has no endpoint

`collection_account.secret_*` is decrypted only inside the collection
worker. There is **no route that returns a persona secret**, and
`PersonaVault` has no method that could serve one -- `use()` hands the
plaintext to a callback and never returns it. `collection_account.reveal`
exists as a permission for a break-glass path that is deliberately not
wired to HTTP.

What IS exposed is persona *health*: whether a persona is usable, when it
was last used, and why it was suspended. An operator who cannot see that a
persona is burnt will keep using it.

## docs/16 L3 is unresolved and this router says so

Every response that could lead to a persona touching a forum carries the
notice. The software will happily drive an account into a site; whether
you may is not a software question, and in several jurisdictions accessing
a system with credentials registered under a false identity engages
computer-misuse law regardless of intent.

## Every listing is filtered by the caller's own ceiling

`collect.source.classification` defaults to AMBER and can be RED, and
until 2026-09-02 only the document and watch-hit routes honoured it. The
older routes -- due, unhealthy, runs, personas, egress -- handed a RED
source's name, URL, health and run history to any global
`collection.read` holder, while the posts from that source were correctly
withheld. The name of a RED source is frequently the finding. So every
route here that LISTS sources, runs, personas or documents, or answers a
question about one source, passes `user_ceiling(...)[0].name` to the
service; the service treats `None` as the worker path with no filter, and
nothing in this file ever passes `None`. The two routes that take no
ceiling -- `/sources/{id}/run` and `/personas/{id}/status` -- are writes
to one row the caller named by id, under `collection.run` and
`collection_account.manage` respectively, and neither returns a source's
name or URL; they are not listings and are not what this section is
about.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.collection import (
    CollectionError,
    CollectionNotFound,
    CollectionService,
    PersonaUnavailable,
    PersonaVault,
)
from noctornal_api.http.deps import (
    CurrentUser,
    get_conn,
    require,
    require_global,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit

router = APIRouter(prefix="/collection", tags=["collection"])

#: Repeated on every route that can put a persona in front of a site.
L3_NOTICE = (
    "docs/16 L3 is BLOCKING and unresolved: authority to operate a covert "
    "persona is per-jurisdiction, and passive collection (reading a public "
    "forum) may be authorised separately from active collection (posting, "
    "messaging, purchasing). This software records the distinction; it "
    "cannot confer the authority for either."
)


@router.get("/sources/due", response_model=dict)
def due_sources(
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """What is ready to poll. Reports; does not act.

    A newly-added source is due immediately rather than after a full
    interval -- that was a real defect, and a source that sits idle on its
    first day looks broken to whoever just configured it.

    Filtered by the caller's own ceiling. A source above it is not "due"
    to this caller; its name and URL are what its label protects.
    """
    clearance, _ = user_ceiling(conn, user.user_id)
    due = CollectionService(conn).due_sources(clearance=clearance.name)
    return {"due": [{**d, "id": str(d["id"])} for d in due],
            "count": len(due),
            "notice": ("Nothing polls itself. Call /sources/{id}/run to "
                       "poll one source once. " + L3_NOTICE)}


@router.get("/sources/unhealthy", response_model=dict)
def unhealthy(
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Sources whose parser has stopped matching.

    This is the endpoint that makes silent failure loud. A parser that
    stopped matching is usually the site changing its markup, and it fails
    by returning zero items rather than by raising -- so without somebody
    watching this list, a feed goes quiet and the case simply stops
    growing.

    `never_polled` is reported separately rather than mixed in. A source
    that has never run is not broken, and listing it here alongside a
    parser that genuinely stopped matching pads the alert with non-alerts
    — which is how a list that exists to be watched stops being watched.
    """
    clearance, _ = user_ceiling(conn, user.user_id)
    svc = CollectionService(conn)
    rows = svc.unhealthy_sources(clearance=clearance.name)
    never = svc.never_polled_sources(clearance=clearance.name)
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
) -> dict:
    """Poll ONE source, ONCE.

    Every outcome becomes a `collection_run` row including the failures,
    because parser health is only knowable if failures are recorded as
    carefully as successes. Metered under `capture` because it is the same
    shape of work -- one call that stores rows at machine rate -- and a
    loop floods `collect.document` and the watch-hit queue rather than the
    server. Until 2026-09-02 this docstring said each poll "can raise a
    proposal per new item"; it cannot. A poll writes documents and watch
    hits and never touches `collect.proposal` -- the `Adapter` docstring in
    collection.py says where items actually go and why the proposal wiring
    is deliberately not made.
    """
    try:
        result = CollectionService(conn).run_once(
            source_id, actor_id=user.user_id, persona_id=body.persona_id,
            watch_id=body.watch_id)
    except PersonaUnavailable as exc:
        # 409 rather than 403: the caller is allowed, the persona is not
        # usable -- suspended, burnt, or cooling down.
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {
        "run_id": str(result.run_id),
        "items_seen": result.items_seen,
        "items_new": result.items_new,
        "watch_hits": result.watch_hits,
        "error": result.error,
        # What the run could not do while otherwise succeeding. A watch
        # whose regex will not compile matches nothing for ever, and until
        # 2026-08-07 that was swallowed: the run reported OK and the watch
        # looked like one that simply had not fired.
        "warnings": result.warnings,
        "notice": L3_NOTICE,
    }


@router.get("/personas", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def personas(
    user: CurrentUser = Depends(require_global("collection_account.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Persona HEALTH. Never a secret.

    Invariant 7: credentials never leave the collector. There is no route
    that returns `secret_*`, and `PersonaVault.use()` hands the plaintext
    to a callback rather than returning it, so no caller here could serve
    one even by mistake.

    What an operator needs instead is whether a persona is usable and why
    not -- a burnt persona that still looks available is one somebody will
    keep using.

    Each row names the persona's SOURCE, so the list is filtered by the
    caller's ceiling against the source's label (`PersonaVault.personas`
    says how, and why a source-less persona is always shown).
    """
    clearance, _ = user_ceiling(conn, user.user_id)
    return {
        "personas": PersonaVault(conn).personas(clearance=clearance.name),
        "notice": ("Secrets are never returned by any endpoint. " + L3_NOTICE),
    }


class PersonaStatusBody(BaseModel):
    status: str
    reason: str = Field(min_length=5)


@router.post("/personas/{persona_id}/status", response_model=dict)
def set_persona_status(
    persona_id: UUID, body: PersonaStatusBody,
    user: CurrentUser = Depends(require_global("collection_account.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Suspend or restore a persona, with a reason.

    The reason is what a later operator reads when deciding whether the
    persona is safe to use again. "Burnt" and "cooling down after a rate
    limit" are the same status to a scheduler and completely different
    facts to a human.
    """
    try:
        PersonaVault(conn).set_status(
            persona_id, body.status, actor_id=user.user_id,
            reason=body.reason)
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {"persona_id": str(persona_id), "status": body.status}


@router.get("/sources/{source_id}/egress", response_model=dict)
def egress_separation(
    source_id: UUID,
    user: CurrentUser = Depends(require_global("collection_account.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Personas that would share an egress path against one source.

    Two personas reaching the same forum from one address is the cheapest
    correlation an adversary gets, and it is invisible from inside a
    single persona's own view -- which is why this is a question you have
    to ask deliberately rather than something the system warns about
    while you work.

    404 for a source above the caller's ceiling, and for one that does
    not exist, indistinguishably: the notice below says an empty result
    means no shared egress was found, so answering an AMBER caller with
    `[]` about a RED source would report "clean" about a forum they are
    not cleared to know exists.
    """
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        findings = PersonaVault(conn).check_egress_separation(
            source_id, clearance=clearance.name)
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

    The failures are the point. A run that fetched 200 items and parsed
    zero is a broken parser, and it is indistinguishable from a quiet feed
    unless the run is recorded either way.

    Filtered by the caller's ceiling against the SOURCE's label. This was
    a raw SELECT on `collection_run` with no join, so it could not have
    filtered even if asked: the label lives on the source.
    """
    clearance, _ = user_ceiling(conn, user.user_id)
    rows = CollectionService(conn).runs(
        source_id=source_id, limit=limit, clearance=clearance.name)
    return {"runs": rows, "count": len(rows),
            "note": ("A run with items_seen > 0 and items_new = 0 across "
                     "several polls is usually a parser that stopped "
                     "matching, not a quiet source.")}


# ---------------------------------------------------------------------------
# The read path — what the collector actually collected
# ---------------------------------------------------------------------------
#
# Until 2026-08-10 the only observable trace of a poll was three integers
# on a run card: items_seen, items_new, watch_hits. A watch could fire four
# hundred times and the analyst saw the number 400 and could not open one
# of them. `collect.document` and `collect.watch_hit` were written by the
# collector and read by nothing.

@router.get("/documents", response_model=dict)
def documents(
    source_id: UUID | None = Query(default=None),
    triage_state: str | None = Query(default=None),
    limit: int = Query(100, ge=1, le=500),
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Collected documents, newest first.

    NOT case-scoped: `collect.document` has no `case_id` because a
    document hangs off a SOURCE, and one forum post is evidence in
    however many cases cite it. Gated on the global `collection.read` and
    filtered by classification — which defaults to AMBER and can be
    higher, so this filter is doing real work rather than being defensive
    habit.
    """
    clearance, _ = user_ceiling(conn, user.user_id)
    docs = CollectionService(conn).documents(
        clearance=clearance.name, source_id=source_id,
        triage_state=triage_state, limit=limit)
    return {"documents": docs, "count": len(docs),
            "note": ("Bodies are excerpted to 400 characters; `truncated` "
                     "says which. Purged documents are omitted entirely "
                     "rather than returned with an empty body.")}


class TriageBody(BaseModel):
    state: str


@router.post("/documents/{document_id}/triage", response_model=dict)
def triage_document(
    document_id: UUID, body: TriageBody,
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Move a document between the four triage states the pane filters on.

    Gated exactly as reading documents is -- global `collection.read`,
    and the document's own classification against the caller's ceiling
    inside the service's UPDATE -- because triage is the reader's verb:
    the analyst working the Collected list is the one who decides a post
    is noise or worth a look. NOT case-scoped, for the reason `documents`
    gives: a document hangs off a source, not a case.

    A state outside the four is a 400 carrying the list; a document the
    caller cannot see is a 404, the same 404 a random UUID gets.
    """
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        return CollectionService(conn).set_document_triage(
            document_id, body.state, actor_id=user.user_id,
            clearance=clearance.name)
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

    Case-scoped, because `collect.watch` carries `case_id` even though the
    document it matched does not.

    Suppressed hits are INCLUDED, carrying their reason. Hiding them would
    make a watch that is drowning in one recurring thread look like a
    watch that is quiet, and those need opposite responses.
    """
    clearance, _ = user_ceiling(conn, user.user_id)
    hits = CollectionService(conn).watch_hits(
        case_id, clearance=clearance.name,
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
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        result = CollectionService(conn).acknowledge_hit(
            hit_id, user_id=user.user_id, clearance=clearance.name)
    except CollectionError as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    return result


class SuppressBody(BaseModel):
    #: No `min_length` here on purpose. The floor is the service's
    #: (`MIN_SUPPRESS_REASON_LENGTH`), so every caller -- this route, a
    #: script, a future digest job -- meets the same rule, and a short
    #: reason is a 400 carrying the service's words rather than a 422
    #: from a validator that restates them.
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
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        return CollectionService(conn).suppress_hit(
            case_id, hit_id, actor_id=user.user_id, reason=body.reason,
            clearance=clearance.name)
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
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        return CollectionService(conn).unsuppress_hit(
            case_id, hit_id, actor_id=user.user_id, clearance=clearance.name)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
