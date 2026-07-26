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
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.collection import (
    CollectionError,
    CollectionService,
    PersonaUnavailable,
    PersonaVault,
)
from noctornal_api.http.deps import CurrentUser, get_conn, require_global
from noctornal_api.http.errors import Problem
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
    """
    due = CollectionService(conn).due_sources()
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
    svc = CollectionService(conn)
    rows = svc.unhealthy_sources()
    never = svc.never_polled_sources()
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
    carefully as successes. Metered under `capture` for the same reason
    that limit exists: each poll can raise a proposal per new item, and a
    loop floods the analyst's triage queue rather than the server.
    """
    try:
        result = CollectionService(conn).run_once(
            source_id, actor_id=user.user_id, persona_id=body.persona_id,
            watch_id=body.watch_id)
    except PersonaUnavailable as exc:
        # 409 rather than 403: the caller is allowed, the persona is not
        # usable -- suspended, burnt, or cooling down.
        raise Problem(409, "Conflict", str(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    return {
        "run_id": str(result.run_id),
        "items_seen": result.items_seen,
        "items_new": result.items_new,
        "watch_hits": result.watch_hits,
        "error": result.error,
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
    """
    # Every column EXCEPT secret_ciphertext / secret_key_id / secret_nonce,
    # named explicitly rather than selected with * so that adding a
    # secret-bearing column later cannot quietly start returning it.
    rows = conn.execute(
        """SELECT a.id, a.handle, s.name, s.base_url, a.status,
                  a.last_used_at, a.burn_reason, a.cooldown_until,
                  a.approved_by, a.secret_rotated_at
             FROM collect.collection_account a
             LEFT JOIN collect.source s ON s.id = a.source_id
            ORDER BY a.status, a.handle""").fetchall()
    return {
        "personas": [
            {"id": str(r[0]), "handle": r[1], "source_name": r[2],
             "source_url": r[3], "status": r[4],
             "last_used_at": r[5].isoformat() if r[5] else None,
             "burn_reason": r[6],
             "cooldown_until": r[7].isoformat() if r[7] else None,
             "approved": r[8] is not None,
             "secret_rotated_at": r[9].isoformat() if r[9] else None}
            for r in rows],
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
        raise Problem(400, "Invalid request", str(exc)) from exc
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
    """
    findings = PersonaVault(conn).check_egress_separation(source_id)
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
    """
    rows = conn.execute(
        """SELECT id, source_id, started_at, finished_at, status,
                  items_seen, items_new, http_status, error_class, error_detail
             FROM collect.collection_run
            WHERE (%s::uuid IS NULL OR source_id = %s)
            ORDER BY started_at DESC LIMIT %s""",
        (source_id, source_id, limit)).fetchall()
    return {"runs": [
        {"id": str(r[0]), "source_id": str(r[1]),
         "started_at": r[2].isoformat() if r[2] else None,
         "finished_at": r[3].isoformat() if r[3] else None,
         "status": r[4], "items_seen": r[5], "items_new": r[6],
         "http_status": r[7], "error_class": r[8], "error_detail": r[9]}
        for r in rows], "count": len(rows),
        "note": ("A run with items_seen > 0 and items_new = 0 across "
                 "several polls is usually a parser that stopped matching, "
                 "not a quiet source.")}
