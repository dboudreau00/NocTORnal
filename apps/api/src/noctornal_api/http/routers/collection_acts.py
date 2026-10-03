"""Persona acts over HTTP: the act queue's answer to the routes that queue
an act, and the caller's own acts (ROADMAP-REMAINING "A collector process",
2026-10-02).

A route that makes a persona act (a Telegram chat looked up, joined, its
membership checked or marked, rebound; a Poll now of a source a persona
reads) queues it in `collect.persona_act` through `act_answer`, which
waits a short bounded time for the collector and answers with the act's
outcome, exactly as the route answered before, or 202 with the act while
it is still queued. The request thread never waits longer than
NOCTORNAL_ACT_WAIT_SECONDS, and never more than 25 seconds.

`GET /collection/acts` lists the caller's own acts, newest first, within
their ceiling now; `GET /collection/acts/{id}` is one of them, with the
body or the refusal the route would have given once it has run; a PENDING
act can be cancelled. Another person's act, and one held above the caller,
answer exactly as a missing one. Nothing here ever shows an act's
parameters or a credential.
"""
from __future__ import annotations

from typing import Literal
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from noctornal_api import persona_acts
from noctornal_api.http.deps import CurrentUser, get_conn, require_global, user_ceiling
from noctornal_api.http.errors import Problem
from noctornal_api.http.routers.collection import get_adapters

router = APIRouter(prefix="/collection/acts", tags=["collection"])

ACT_NOT_FOUND = "no such persona act, or it is not yours to see"


def _raise_problem(act: dict) -> None:
    problem = (act.get("result") or {}).get("problem") or {}
    raise Problem(int(problem.get("status") or 500),
                  problem.get("title") or "Internal error",
                  problem.get("detail") or persona_acts.FAILED_SENTENCE)


def act_answer(conn: psycopg.Connection, user: CurrentUser, *, kind: str,
               source_id: UUID | None, classification: str, params: dict,
               adapters, factory):
    """Queue the act and answer for it: the route's own body once it is
    DONE, the route's own refusal once it is REFUSED or FAILED, and 202
    with the act while the collector has not finished it."""
    act = persona_acts.submit(
        conn, user_id=user.user_id, session_id=user.session_id,
        mfa_at=user.session_mfa_at, kind=kind, params=params,
        classification=classification, source_id=source_id)
    body = None
    if persona_acts.inline_mode():
        act, body = persona_acts.run_inline(conn, act, adapters=adapters,
                                            transport_factory=factory)
    else:
        act = persona_acts.wait(conn, act["id"], user_id=user.user_id,
                                seconds=persona_acts.wait_seconds())
    if act is None:
        raise Problem(404, "Not found", ACT_NOT_FOUND)
    if act["status"] in persona_acts.LIVE:
        return JSONResponse(status_code=202, content={
            "act": persona_acts.public(act), "queued": True,
            "notice": persona_acts.QUEUED_NOTICE})
    if act["status"] != "DONE":
        _raise_problem(act)
    if body is not None:
        return body
    clearance, _ = user_ceiling(conn, user.user_id)
    return persona_acts.served_body(conn, act, clearance=clearance.name,
                                    adapters=adapters)


@router.get("", response_model=dict)
def list_acts(
    status: Literal["PENDING", "RUNNING", "DONE", "REFUSED", "FAILED",
                    "EXPIRED", "CANCELLED"] | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(require_global("collection.run")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The caller's own persona acts, newest first, within their ceiling."""
    clearance, _ = user_ceiling(conn, user.user_id)
    acts = persona_acts.listing(conn, user_id=user.user_id,
                                clearance=clearance.name, status=status,
                                limit=limit)
    return {"acts": [persona_acts.public(a) for a in acts], "count": len(acts),
            "inline": persona_acts.inline_mode()}


@router.get("/{act_id}", response_model=dict)
def get_act(
    act_id: UUID,
    user: CurrentUser = Depends(require_global("collection.run")),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """One of the caller's acts. Once it has run, `body` is what the route
    answers for it, or `problem` the refusal it gives."""
    clearance, _ = user_ceiling(conn, user.user_id)
    act = persona_acts.read(conn, act_id, user_id=user.user_id,
                            clearance=clearance.name)
    if act is None:
        raise Problem(404, "Not found", ACT_NOT_FOUND)
    body = None
    if act["status"] == "DONE":
        body = persona_acts.served_body(conn, act, clearance=clearance.name,
                                        adapters=adapters)
    return {"act": persona_acts.public(act), "body": body,
            "problem": (act.get("result") or {}).get("problem")
            if act["status"] in persona_acts.FINISHED and act["status"] != "DONE"
            else None}


@router.post("/{act_id}/cancel", response_model=dict)
def cancel_act(
    act_id: UUID,
    user: CurrentUser = Depends(require_global("collection.run")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Cancel one of the caller's acts the collector has not started. One
    already started or finished is a 409 that says which."""
    clearance, _ = user_ceiling(conn, user.user_id)
    act, cancelled = persona_acts.cancel(conn, act_id, user_id=user.user_id,
                                         clearance=clearance.name)
    if act is None:
        raise Problem(404, "Not found", ACT_NOT_FOUND)
    if not cancelled:
        raise Problem(409, "Conflict",
                      "This act has already started or finished, so it cannot "
                      "be cancelled.")
    return {"act": persona_acts.public(act)}
