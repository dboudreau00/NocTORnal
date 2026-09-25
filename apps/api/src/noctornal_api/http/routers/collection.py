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
nothing in this file ever passes `None`.

`/sources/{id}/run` was exempted from that rule for half a day on
2026-09-02, and this docstring justified the exemption by asserting the
route "neither returns a source's name or URL". That was false, and it
was the one sentence a maintainer would have trusted instead of reading
the route. The poll returns `error`, which is the redacted adapter
failure, and the SSRF guard writes the HOST into it ("cannot resolve
{host}", "{host} resolves into private address space", "{host} is a
cloud metadata endpoint"); `redact` masks credential shapes and leaves
hostnames alone. The route now resolves the caller's ceiling like every
other, and a source above it gets the same 404 a nonexistent id gets --
which closes the existence oracle in the old 400-versus-200 split as
well, and stops a sub-cleared caller from making the collector touch a
forum on their say-so.

## The one route that reads the readiness register

`/sources/{id}/run` refuses with 409 while any BLOCKING readiness check
fails, naming them. It is the only route here that does, because it is
the only one that puts this software in front of somebody else's system:
every other route reports on what already happened.

The four (readiness.BLOCKING_CHECKS) are the ones an operator must
settle before real material arrives -- no prohibited-content policy and
no named person to escalate to, retention periods still on their seeded
placeholders, no security officer to review a break-glass or read the
audit trail, no sample origin so nothing collected can be retrieved.
Running a covert poll against a real target on a deployment in that
state is not a configuration mistake that can be tidied up afterwards;
the material is in the building and the decisions were never taken.

Until 2026-09-10 the register was a pane and nothing more: every one of
those four could be red for a month and this route would poll happily,
because the only consequence of a failed check was a row nobody had to
open. `blocking_failures` runs only the four, so a poll does not wait on
a Redis PING or a MinIO round trip to find out whether it may proceed.

The gate is not this route's alone, and it must not become so.
`scripts/collection_poll.py` -- the cron in infra/production/compose.yml,
which polls every due source every five minutes with nobody reading the
output -- asks the same question once per pass and refuses the whole pass
in the same words. A gate on the attended path only would stop the
analyst who pressed a button and wave the unattended runner through,
which is the collection nobody is watching.

`/personas/{id}/status` was the last route here that took no ceiling,
and it was a WRITE: an AMBER holder of `collection_account.manage` could
burn, lock or clear the cooldown on a persona whose source the listing
hid from them, by id. The previous version of this paragraph recorded
that the route was "not an existence oracle" only because
`PersonaVault.set_status` ran a bare UPDATE and answered 200 whether or
not it matched -- a write that did not happen, reported as one that did
-- and deferred both defects to a later decision. Closed 2026-09-09: the
route resolves the caller's ceiling like every other, the service gates
the UPDATE on the source's label and checks that it matched, and an
unknown id and an over-ceiling one get the same 404 `/sources/{id}/run`
gives. No route in this file takes no ceiling any more.
"""
from __future__ import annotations

from datetime import timedelta
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.collection import (
    PERSONA_VISIBLE_SQL,
    SOURCE_KINDS,
    Adapter,
    CollectionBusy,
    CollectionError,
    CollectionNotFound,
    CollectionService,
    PersonaResting,
    PersonaUnavailable,
    PersonaVault,
    SourceRefused,
    _attr,
    active_window,
    default_adapters,
    header_text_problem,
)
from noctornal_api.collection_authority import (
    SOURCE_CEILING_ENV,
    AuthorityError,
    source_ceiling,
)
from noctornal_api import forum_adapters  # F3 and F4 (2026-09-24)
from noctornal_api import telegram_service  # F5.2 and F5.3
from noctornal_api.db import SystemPurpose, system_connection
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_global,
    get_conn,
    require,
    require_global,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.readiness import blocking_failures
from noctornal_api.security.access import AccessResolutionError, evaluate
from noctornal_api.stores import PgAccessResolver

router = APIRouter(prefix="/collection", tags=["collection"])

#: Repeated on every route that can put a persona in front of a site. The
#: legal-review item by its register number, not a design document's path
#: (ux19-copy developer-speak-in-copy, 2026-09-23). Rewritten 2026-09-24
#: (docs/00 decision 69): the old wording said the software "records the distinction"
#: between passive and active collection, and nothing did; it now refuses
#: every forum and Telegram read no confirmed authority covers, and has no
#: active scope because nothing in it engages.
L3_NOTICE = (
    "Legal review item L3 is still open: authority to read a forum or a "
    "chat, publicly or as a member, is decided per jurisdiction. This "
    "software refuses every forum and Telegram read that no confirmed "
    "authority covers, and records who declared and who confirmed it; it "
    "cannot confer the authority, and nothing in it posts, messages or "
    "purchases."
)


def get_adapters() -> dict[str, Adapter]:
    """THE adapter registry for the routes (2026-09-24): an HTTP test
    registers a stub adapter through app.dependency_overrides instead of
    patching the module."""
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
    """409 while any BLOCKING readiness check fails, naming them: one
    sentence for the run route and the attended persona acts, never a copy
    (2026-09-24)."""
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

    A newly-added source is due immediately rather than after a full
    interval -- that was a real defect, and a source that sits idle on its
    first day looks broken to whoever just configured it.

    Filtered by the caller's own ceiling. A source above it is not "due"
    to this caller; its name and URL are what its label protects.
    """
    clearance, _ = user_ceiling(conn, user.user_id)
    svc = CollectionService(conn, adapters)
    due = svc.due_sources(clearance=clearance.name)
    # 2026-09-24: what waits on a person, by reason. A held source is
    # not polled, not rescheduled and not a failure.
    held = [{**h, "id": str(h["id"])}
            for h in svc.held_sources(clearance=clearance.name)]
    # F5.3 (2026-09-24). A due Telegram chat names its chat and exit.
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
    """Whether THIS caller's Poll now would be refused, and why, before
    they press it (ux12-feeds:poll-now-one-click-and-blocked, 2026-09-23).

    The pane offered an enabled Poll now on every due source while the
    route refused every poll with a 409 naming the blocking checks, and to
    anyone without `collection.run`, which is every role but COLLECTOR,
    with a 403. The analyst learnt either from an error banner after the
    click. `allowed` is the verb, asked of the gate without writing an
    AUTHZ_DENIED row (a question on a listing is not an attempt); the
    blocking checks are named only to a caller who holds it, because they
    are the refusal that caller would get, and nobody else is refused for
    them. The poll route still decides: this is the button's state.
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
    adapters: dict = Depends(get_adapters),
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

    404 for a source above the caller's ceiling, and for one that does not
    exist, indistinguishably. This route was exempted from the ceiling
    pass earlier on 2026-09-02 on the reasoning that a poll returns no
    name or URL; `error` below is the redacted adapter failure, and the
    SSRF guard names the HOST in it, so the exemption was disclosing
    exactly what the label protects. The 400-versus-200 split was an
    existence oracle on top of it, and the poll itself ran against a
    source the caller was not cleared to know about.

    409 while any BLOCKING readiness check fails, before anything else is
    read or written. See "The one route that reads the readiness
    register" above for which four and why; the refusal names them and
    sends the caller to `GET /admin/readiness` for the evidence and the
    action behind each, because a refusal an operator cannot act on is
    just an outage.

    409 also for a persona that is not usable, and for a source another
    runner is already polling -- all three are "you are allowed, this
    cannot run right now", and the detail says which. Only the last is
    worth retrying immediately.
    """
    # BEFORE the ceiling lookup on purpose: this is a fact about the
    # deployment and not about the caller or the source, so resolving a
    # clearance first would spend a query to answer a question that
    # cannot change the outcome. It is not an oracle either -- the caller
    # already holds global `collection.run`, and the answer is the same
    # for every source id including ones that do not exist.
    #
    # 409 is also what an unusable persona and an already-running poll get
    # below. All three are "you are allowed, something else is not ready";
    # the detail says which, and naming the failing checks is what makes
    # this one distinguishable to a caller who is not reading this file.
    refuse_unready(conn)
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        # The poll on a system connection (S1, 2026-09-25), as the cron's
        # is: a new item dedupes against every stored version of it and
        # is matched against every case's watches, and a manual run that
        # saw only its caller's documents would store duplicates and miss
        # hits. The caller's ceiling still decides whether the source may
        # be run at all (run_once's 404 below), exactly as before.
        with system_connection(SystemPurpose.COLLECTION, reuse=conn) as sconn:
            result = CollectionService(sconn, adapters).run_once(
                source_id, actor_id=user.user_id, persona_id=body.persona_id,
                watch_id=body.watch_id, clearance=clearance.name)
    except (SourceRefused, PersonaResting, AuthorityError) as exc:
        # ABOVE `except CollectionError`, as CollectionBusy is: each is "you
        # are allowed, this cannot run", and nothing was done. A refused
        # source is configuration, a resting persona is outside its hours,
        # and the confirmer is refused as the runner before any run row;
        # 400 "Invalid request" would tell the caller to
        # fix a request with nothing wrong in it.
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    except PersonaUnavailable as exc:
        # 409 rather than 403: the caller is allowed, the persona is not
        # usable -- suspended, burnt, or cooling down.
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    except CollectionBusy as exc:
        # ABOVE `except CollectionError` and it must stay there: CollectionBusy
        # is a subclass, so until 2026-09-10 it was caught below and answered
        # 400 "Invalid request" -- for a request that was entirely valid and
        # did nothing at all. The case that produces it is the ordinary one
        # the lock exists for and `run_once`'s docstring names: an analyst
        # double-clicking Run, or this pane overlapping the cron in
        # scripts/collection_poll.py. 409 says the true thing, which is that
        # the poll is already happening; 400 told them to fix a request that
        # had nothing wrong with it, and left retrying -- the correct
        # response -- looking like the wrong one.
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {
        "run_id": str(result.run_id),
        "items_seen": result.items_seen,
        "items_new": result.items_new,
        "watch_hits": result.watch_hits,
        "error": result.error,
        # 2026-09-24: BLOCKED and RATE_LIMITED are not failures, and
        # a note (a walk that stopped at its budget) is not a warning.
        "status": result.status,
        "blocked_reason": result.blocked_reason,
        "items_deleted": result.items_deleted,
        "notes": result.notes,
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

    Invariant 7: credentials never leave the vault. There is no route
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
    personas = PersonaVault(conn).personas(clearance=clearance.name)
    # F5.2 (2026-09-24). A Telegram persona row carries its enrolment,
    # hold and chat count; never a secret column.
    personas = telegram_service.attach_persona_facts(conn, personas, clearance.name)
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

    404 for a persona whose source is above the caller's ceiling, and for
    one that does not exist, indistinguishably -- the same answer
    `/sources/{id}/run` gives, for the same reason. Until 2026-09-09 this
    route passed no ceiling and the service checked nothing: an AMBER
    caller could burn a persona on a RED source the persona list hid from
    them, and an unknown id got a 200 for a write that never happened.
    """
    clearance, _ = user_ceiling(conn, user.user_id)
    cooldown = (timedelta(hours=body.cooldown_hours)
                if body.cooldown_hours else None)
    try:
        written = PersonaVault(conn).set_status(
            persona_id, body.status, actor_id=user.user_id,
            reason=body.reason, cooldown=cooldown, clearance=clearance.name)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    answer = {"persona_id": str(persona_id), "status": body.status}
    # 2026-09-24: HEALTHY under a platform's hold or lock changes the
    # person's status only, and the answer says the persona stays paused.
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
    # The reader's compartments too (L1, 2026-09-24): a capture
    # into a compartmented case is stored under the case's keys.
    clearance, held = user_ceiling(conn, user.user_id)
    # Document holds (docs/00 decision 74, 2026-09-24). The caller holds
    # collection.read already (the gate above); placing a document hold
    # needs retention.manage as well, and only such a caller reads a hold's
    # reason (2026-09-25).
    can_hold = _holds(conn, user, "retention.manage")
    docs = CollectionService(conn).documents(
        clearance=clearance.name, compartments=held, source_id=source_id,
        triage_state=triage_state, limit=limit, with_hold_reason=can_hold)
    # F5.3 (2026-09-24). A Telegram document carries its capture record.
    docs = telegram_service.attach_message_meta(conn, docs)
    return {"documents": docs, "count": len(docs),
            "can_hold": can_hold,
            "note": ("Bodies are excerpted to 400 characters; `truncated` "
                     "says which. Purged documents are omitted entirely "
                     "rather than returned with an empty body.")}


# F3 and F4 (2026-09-24). What a forum post or member
# carries beside its text (the signature, the posts it quotes, its
# reactions; a member's profile), read under the document's label, its
# source's label and its compartments, exactly as the list reads the
# document. A document the caller may not see, or one with no forum
# details, is the same 404 a random id gets.
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

    Gated exactly as reading documents is -- global `collection.read`,
    and the document's own classification against the caller's ceiling
    inside the service's UPDATE -- because triage is the reader's verb:
    the analyst working the Collected list is the one who decides a post
    is noise or worth a look. NOT case-scoped, for the reason `documents`
    gives: a document hangs off a source, not a case.

    A state outside the four is a 400 carrying the list; a document the
    caller cannot see is a 404, the same 404 a random UUID gets.
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

    Case-scoped, because `collect.watch` carries `case_id` even though the
    document it matched does not.

    Suppressed hits are INCLUDED, carrying their reason. Hiding them would
    make a watch that is drowning in one recurring thread look like a
    watch that is quiet, and those need opposite responses.
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
# Sources, personas and bindings (the collection foundation, 2026-09-24)
# ---------------------------------------------------------------------------
#
# Until now no route created a source or a persona: only SQL, the seeders and
# the tests did. The console can now add a source, create a persona with NO
# credential (an operator enrols it on the server), say who reads a source
# and through which exit, and deactivate one, each gated, rate limited under
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
    clearance, _ = user_ceiling(conn, user.user_id)
    rows = CollectionService(conn, adapters).sources(clearance=clearance.name)
    manage = _holds(conn, user, "source.manage")
    return {"sources": rows, "count": len(rows),
            "adapters": _adapter_rows(adapters),
            "ceilings": {kind: source_ceiling(kind)[0]
                         for kind in sorted(SOURCE_CEILING_ENV)},
            "kinds": list(SOURCE_KINDS),
            "can_manage": manage,
            "can_bind": manage and _holds(conn, user, "collection_account.manage"),
            # F3 and F4 (2026-09-24). A forum read leaves from this
            # server's own address (development, no proxy, the override
            # set): the Poll now confirmation says so.
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


@router.post("/sources", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("collection.config"))])
def create_source(
    body: SourceCreate,
    user: CurrentUser = Depends(require_global("source.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """A new source. A binding (a persona, or an exit for a persona-less
    read) also needs collection_account.manage, which is step-up. A forum or
    Telegram source is created and then waits: nothing is read until its
    authority is recorded and confirmed by two people."""
    if body.collection_account_id is not None or body.egress_profile_id is not None:
        authorize_global(conn, user, "collection_account.manage")
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        source = CollectionService(conn, adapters).create_source(
            kind=body.kind, name=body.name, base_url=body.base_url,
            parser_key=body.parser_key, classification=body.classification,
            default_reliability=body.default_reliability,
            poll_interval_s=body.poll_interval_s, jitter_pct=body.jitter_pct,
            max_rps=body.max_rps, parser_config=body.parser_config,
            collection_account_id=body.collection_account_id,
            egress_profile_id=body.egress_profile_id, actor_id=user.user_id,
            clearance=clearance.name)
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
                conn: psycopg.Connection, active: bool) -> dict:
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        return CollectionService(conn).set_source_active(
            source_id, active=active, reason=body.reason,
            actor_id=user.user_id, clearance=clearance.name)
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
) -> dict:
    """Stop reading a source, with a reason; 404 above the caller."""
    return _set_active(source_id, body, user, conn, False)


@router.post("/sources/{source_id}/activate", response_model=dict,
             dependencies=[Depends(rate_limit("collection.config"))])
def activate_source(
    source_id: UUID, body: ReasonBody,
    user: CurrentUser = Depends(require_global("source.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Read a source again, with a reason; 404 above the caller."""
    return _set_active(source_id, body, user, conn, True)


@router.get("/runs/{run_id}", response_model=dict)
def run_detail(
    run_id: UUID,
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """One poll with its custody log of what it asked for, read under the
    SOURCE's label: 404 above it, as for an id that is not a run."""
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        return CollectionService(conn).run_detail(run_id,
                                                  clearance=clearance.name)
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
    clearance, _ = user_ceiling(conn, user.user_id)
    if body.venue_source_id is not None and conn.execute(
            """SELECT 1 FROM collect.source WHERE id = %s
                  AND classification <= %s::core.tlp""",
            (body.venue_source_id, clearance.name)).fetchone() is None:
        raise Problem(404, "Not found", "no such source, or it is above your clearance")
    try:
        persona = PersonaVault(conn).create(
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
    clearance, _ = user_ceiling(conn, user.user_id)
    rows = PersonaVault(conn).egress_profiles(clearance=clearance.name)
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
    adapters: dict = Depends(get_adapters),
) -> dict:
    """Who reads a source and through which exit. Needs both permissions,
    and collection_account.manage is step-up. The authority recorded for
    the old binding stops covering the source at once, and the answer says
    so."""
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        return CollectionService(conn, adapters).bind_source(
            source_id, persona_id=body.collection_account_id,
            egress_profile_id=body.egress_profile_id, reason=body.reason,
            reset_cursor=body.reset_cursor, actor_id=user.user_id,
            clearance=clearance.name)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc


def persona_visible(conn: psycopg.Connection, persona_id: UUID,
                    clearance: str) -> bool:
    """For an attended act's route: whether the caller may see the
    persona (set_status's predicate)."""
    return conn.execute(
        f"SELECT 1 FROM collect.collection_account a "
        f"WHERE a.id = %(id)s AND {PERSONA_VISIBLE_SQL}",
        {"id": persona_id, "clearance": clearance}).fetchone() is not None
