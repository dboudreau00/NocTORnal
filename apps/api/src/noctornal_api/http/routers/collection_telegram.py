"""Telegram chats and personas over HTTP (roadmap F5.2 and F5.3,
2026-09-24).

Every route that makes the persona do something Telegram sees (looking a
chat up, joining it, checking its membership, rebinding it to another
persona) is an attended persona act: 409 while a blocking readiness check
fails (the collection router's refuse_unready, one sentence), the
foundation's persona gate with the caller's own clearance, the persona's
act route on the egress proxy, a live confirmed authority, and the
`collection.persona_act` rate limit. Stopping and resuming a chat carry no
act and no limit beyond the global one: stopping is always allowed.

Binding a chat to a persona is a change the foundation keeps behind
collection_account.manage, which is step-up; creating a chat, rebinding one
and marking one as a member chat therefore need it too, and joining needs a
fresh second factor (2026-09-24).

A source above the caller, or a persona the caller may not see, answers
exactly like a missing one. An outcome answers a fixed status and sentence,
never a library's text: the foundation's answers for a wait, a refused
credential and an abandoned session, and Telegram's own for an egress
refusal (503), a transport failure (502) and a chat Telegram will not show
this persona (409).
"""
from __future__ import annotations

from typing import Literal
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from noctornal_api.collection import (
    CollectionError,
    CollectionNotFound,
    attended_answer,
)
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_global,
    get_conn,
    require_global,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.http.routers.collection import (
    L3_NOTICE,
    get_adapters,
    refuse_unready,
)
from noctornal_api.telegram import (
    ReferenceRefused,
    TelegramEgressRefused,
    TelegramProxyBusy,
    TelegramSecretInvalid,
    TelegramTransportFailed,
)
from noctornal_api.telegram_service import (
    TelegramActError,
    TelegramChats,
    set_window,
)

router = APIRouter(prefix="/collection/telegram", tags=["collection"])

EGRESS_ANSWER = ("The egress proxy refused the connection to Telegram. The "
                 "egress log says why.")
TRANSPORT_ANSWER = "Telegram could not be reached. Nothing was changed."
_TITLES = {400: "Invalid request", 404: "Not found", 409: "Conflict",
           422: "Unprocessable", 502: "Bad gateway",
           503: "Service unavailable", 504: "Gateway timeout"}


def get_transport_factory():
    """The Telegram transport the chat routes use; None is Telethon. An HTTP
    test replaces it through app.dependency_overrides with a fake."""
    return None


def _problem(exc: Exception) -> Problem:
    """The fixed answer for an act's outcome."""
    if isinstance(exc, TelegramActError):
        return Problem(exc.status, _TITLES.get(exc.status, "Conflict"), str(exc))
    if isinstance(exc, ReferenceRefused):
        return Problem(400, "Invalid request", str(exc))
    if isinstance(exc, TelegramEgressRefused):
        return Problem(503, "Service unavailable", EGRESS_ANSWER)
    if isinstance(exc, TelegramProxyBusy):
        return Problem(503, "Service unavailable", str(exc))
    if isinstance(exc, TelegramTransportFailed):
        return Problem(502, "Bad gateway", TRANSPORT_ANSWER)
    if isinstance(exc, TelegramSecretInvalid):
        return Problem(409, "Conflict", str(exc))
    # Before the foundation's table, which words every 404 as a persona's:
    # a chat the caller may not see is "no such Telegram chat", exactly as
    # a missing one is.
    if isinstance(exc, CollectionNotFound):
        return Problem(404, "Not found", safe_detail(exc))
    answer = attended_answer(exc)
    if answer is not None:
        status, sentence = answer
        return Problem(status, _TITLES.get(status, "Conflict"), sentence)
    from noctornal_api.collection import SourceBlocked

    if isinstance(exc, SourceBlocked):
        return Problem(409, "Conflict", str(exc))
    return Problem(400, "Invalid request", safe_detail(exc))


def _chats(conn, adapters, factory) -> TelegramChats:
    return TelegramChats(conn, adapters=adapters, transport_factory=factory)


# ---------------------------------------------------------------------------
# Personas
# ---------------------------------------------------------------------------

class WindowBody(BaseModel):
    active_window_utc: str | None = Field(
        default=None,
        pattern=r"^([01][0-9]|2[0-3]):[0-5][0-9]-([01][0-9]|2[0-3]):[0-5][0-9]$")


@router.post("/personas/{persona_id}/window", response_model=dict)
def persona_window(
    persona_id: UUID, body: WindowBody,
    user: CurrentUser = Depends(require_global("collection_account.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """A Telegram persona's active hours in UTC, or none. Outside them the
    persona rests and its chats wait. 404 for a persona the caller may not
    see."""
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        return set_window(conn, persona_id, body.active_window_utc,
                          actor_id=user.user_id, clearance=clearance.name)
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc


# ---------------------------------------------------------------------------
# Chats
# ---------------------------------------------------------------------------

@router.get("/chats", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def list_chats(
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """Telegram chats within the caller's labels, and whether Telegram
    collection is on (the library, the declared ceiling, the proxy), so the
    form offers only what may be added."""
    clearance, held = user_ceiling(conn, user.user_id)
    body = TelegramChats(conn, adapters=adapters).listing(
        clearance=clearance.name, compartments=held)
    body["notice"] = L3_NOTICE
    return body


class ChatCreate(BaseModel):
    persona_id: UUID
    ref: str = Field(min_length=1, max_length=400)
    name: str = Field(min_length=3, max_length=120)
    classification: str = Field(min_length=3, max_length=20)
    default_reliability: str = Field(default="F", pattern="^[A-F]$")
    access_mode: Literal["PUBLIC_READ", "MEMBER"] = "PUBLIC_READ"
    poll_interval_s: int = Field(default=1800, ge=300, le=7 * 86400)
    jitter_pct: int = Field(default=25, ge=0, le=50)
    max_rps: float = Field(default=0.2, ge=0.05, le=1.0)


@router.post("/chats", response_model=dict, status_code=201,
             dependencies=[Depends(require_global("source.manage")),
                           Depends(require_global("collection.run")),
                           Depends(rate_limit("collection.persona_act"))])
def create_chat(
    body: ChatCreate,
    user: CurrentUser = Depends(require_global("collection_account.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
    factory=Depends(get_transport_factory),
) -> dict:
    """Look a chat up as the persona and add it as a source read by that
    persona. A reference Telegram does not resolve and a chat already added
    by somebody the caller cannot see answer the same."""
    refuse_unready(conn)
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        return _chats(conn, adapters, factory).create(
            persona_id=body.persona_id, ref=body.ref, name=body.name,
            classification=body.classification,
            default_reliability=body.default_reliability,
            access_mode=body.access_mode, poll_interval_s=body.poll_interval_s,
            jitter_pct=body.jitter_pct, max_rps=body.max_rps,
            actor_id=user.user_id, clearance=clearance.name)
    except CollectionError as exc:
        raise _problem(exc) from None


class JoinBody(BaseModel):
    acknowledge_overt: Literal[True]
    note: str = Field(min_length=10, max_length=500)


@router.post("/chats/{source_id}/join", response_model=dict,
             dependencies=[Depends(rate_limit("collection.persona_act"))])
def join_chat(
    source_id: UUID, body: JoinBody,
    user: CurrentUser = Depends(require_global("collection.run")),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
    factory=Depends(get_transport_factory),
) -> dict:
    """Join a member chat as the persona: an overt act the chat's
    administrators see. A fresh second factor, and the chat's member
    authority target confirmed first."""
    authorize_global(conn, user, "collection.run", force_step_up=True)
    refuse_unready(conn)
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        return _chats(conn, adapters, factory).join(
            source_id, note=body.note, actor_id=user.user_id,
            clearance=clearance.name)
    except CollectionError as exc:
        raise _problem(exc) from None


class ReasonBody(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


class RebindBody(BaseModel):
    persona_id: UUID
    reason: str = Field(min_length=5, max_length=500)


@router.post("/chats/{source_id}/persona", response_model=dict,
             dependencies=[Depends(require_global("source.manage")),
                           Depends(require_global("collection.run")),
                           Depends(rate_limit("collection.persona_act"))])
def rebind_chat(
    source_id: UUID, body: RebindBody,
    user: CurrentUser = Depends(require_global("collection_account.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
    factory=Depends(get_transport_factory),
) -> dict:
    """Read a chat through another Telegram persona, resolved through that
    persona first."""
    refuse_unready(conn)
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        return _chats(conn, adapters, factory).rebind(
            source_id, persona_id=body.persona_id, reason=body.reason,
            actor_id=user.user_id, clearance=clearance.name)
    except CollectionError as exc:
        raise _problem(exc) from None


@router.post("/chats/{source_id}/member", response_model=dict,
             dependencies=[Depends(require_global("source.manage")),
                           Depends(require_global("collection.run")),
                           Depends(rate_limit("collection.persona_act"))])
def mark_member_chat(
    source_id: UUID, body: ReasonBody,
    user: CurrentUser = Depends(require_global("collection_account.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
    factory=Depends(get_transport_factory),
) -> dict:
    """Mark a public chat as a member chat (never back), then check the
    persona's membership without joining."""
    refuse_unready(conn)
    clearance, _ = user_ceiling(conn, user.user_id)
    chats = _chats(conn, adapters, factory)
    try:
        return chats.mark_member(source_id, reason=body.reason,
                                 actor_id=user.user_id, clearance=clearance.name)
    except CollectionError as exc:
        problem = _problem(exc)
        if problem.status == 409 and not isinstance(exc, TelegramActError):
            problem.detail = ("The chat is now a member chat. "
                              + (problem.detail or ""))
        raise problem from None


@router.post("/chats/{source_id}/membership", response_model=dict,
             dependencies=[Depends(require_global("source.manage")),
                           Depends(rate_limit("collection.persona_act"))])
def check_membership(
    source_id: UUID,
    user: CurrentUser = Depends(require_global("collection.run")),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
    factory=Depends(get_transport_factory),
) -> dict:
    """Whether Telegram reports the persona a member of a member chat. Reads
    the persona's own view of the chat and never joins."""
    refuse_unready(conn)
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        return _chats(conn, adapters, factory).check_membership(
            source_id, actor_id=user.user_id, clearance=clearance.name)
    except CollectionError as exc:
        raise _problem(exc) from None


def _set_active(source_id, body, user, conn, adapters, active: bool) -> dict:
    clearance, _ = user_ceiling(conn, user.user_id)
    try:
        return _chats(conn, adapters, None).set_active(
            source_id, active=active, reason=body.reason, actor_id=user.user_id,
            clearance=clearance.name)
    except CollectionError as exc:
        raise _problem(exc) from None


@router.post("/chats/{source_id}/deactivate", response_model=dict)
def stop_chat(
    source_id: UUID, body: ReasonBody,
    user: CurrentUser = Depends(require_global("source.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """Stop reading a chat. No persona act and no rate limit beyond the
    global one: stopping is always allowed."""
    return _set_active(source_id, body, user, conn, adapters, False)


@router.post("/chats/{source_id}/resume", response_model=dict)
def resume_chat(
    source_id: UUID, body: ReasonBody,
    user: CurrentUser = Depends(require_global("source.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """Read a stopped chat again. Its authority and its refusals decide
    whether it is read; a chat that became a supergroup is not resumed."""
    return _set_active(source_id, body, user, conn, adapters, True)
