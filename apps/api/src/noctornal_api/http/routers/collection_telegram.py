"""Telegram chats and personas over HTTP.

A route that makes the persona do something Telegram sees is an attended persona act, held to the
readiness register (`refuse_unready`), the persona gate at the caller's clearance, the persona's
egress route, a live confirmed authority and the `collection.persona_act` limit. The route checks
what it can first, then queues the act for the collector (NOCTORNAL_COLLECTOR_INLINE runs it
here). Binding, creating, rebinding and marking a chat need the step-up
`collection_account.manage`, and joining a fresh second factor; stopping is always allowed. A
source or persona the caller may not see answers as a missing one, and an outcome is a fixed
status and sentence, never a library's text.
"""
from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends
from pydantic import AfterValidator, BaseModel, Field

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
    _CONFIG,
    L3_NOTICE,
    get_adapters,
    refuse_unready,
)
from noctornal_api.security.access import AccessResolutionError, tlp_from_name
from noctornal_api.telegram import (
    ReferenceRefused,
    TelegramEgressRefused,
    TelegramProxyBusy,
    TelegramSecretInvalid,
    TelegramTransportFailed,
    clean_text,
)
from noctornal_api.telegram_service import (
    TelegramActError,
    TelegramChats,
    check_create_request,
    normal_reference,
    set_window,
)

router = APIRouter(prefix="/collection/telegram", tags=["collection"])


def _storable(value: str) -> str:
    """Postgres cannot store U+0000, which pydantic accepts, so `clean_text` swaps it (and a lone
    surrogate) for U+FFFD, one character for one, keeping the field's length limits. A second wall:
    `http/body_ceiling.py` already refuses a request body with a NUL escape."""
    return clean_text(value, len(value)) or ""


#: Free text a route queues in an act's parameters.
Storable = Annotated[str, AfterValidator(_storable)]

EGRESS_ANSWER = ("The egress proxy refused the connection to Telegram. The "
                 "egress log says why.")
TRANSPORT_ANSWER = "Telegram could not be reached. Nothing was changed."
_TITLES = {400: "Invalid request", 404: "Not found", 409: "Conflict",
           422: "Unprocessable", 502: "Bad gateway",
           503: "Service unavailable", 504: "Gateway timeout"}


def get_transport_factory():
    """The Telegram transport the chat routes use; None is Telethon. An HTTP test swaps in a fake
    through app.dependency_overrides."""
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


MEMBER_MARKED = "The chat is now a member chat. "


def act_problem(kind: str, exc: Exception) -> Problem:
    """The answer for a Telegram act's outcome, whichever process ran it: `_problem`, and for a
    mark as member the sentence that says the mark stood."""
    problem = _problem(exc)
    if (kind == "TELEGRAM_MARK_MEMBER" and problem.status == 409
            and not isinstance(exc, TelegramActError)):
        problem.detail = MEMBER_MARKED + (problem.detail or "")
    return problem


def _chats(conn, adapters, factory) -> TelegramChats:
    return TelegramChats(conn, adapters=adapters, transport_factory=factory)


def _act(conn, user, kind: str, *, source_id: UUID | None, classification: str,
         params: dict, adapters, factory):
    """Queue the act for the collector, the one process that holds the persona key, and answer
    with its outcome once it has run, or 202 while it waits. Development's inline mode runs it
    here."""
    from noctornal_api.http.routers.collection_acts import act_answer

    return act_answer(conn, user, kind=kind, source_id=source_id,
                      classification=classification, params=params,
                      adapters=adapters, factory=factory)


def _chat_label(conn, source_id: UUID, clearance: str,
                compartments=None) -> str:
    """The chat's source label, at which its act is held. A chat the caller may not see (its label
    above them, or a compartment they do not hold) answers as a missing one, before anything is
    queued."""
    from noctornal_api.telegram_service import _chat_row

    try:
        return _chat_row(conn, source_id, clearance,
                         compartments)["classification"]
    except CollectionNotFound as exc:
        raise _problem(exc) from None


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
    # Written on a system connection: personas are read-only to the request role (0179).
    sconn: psycopg.Connection = Depends(_CONFIG),
) -> dict:
    """A Telegram persona's active hours in UTC, or none. Outside them the
    persona rests and its chats wait. 404 for a persona the caller may not
    see."""
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        return set_window(sconn, persona_id, body.active_window_utc,
                          actor_id=user.user_id, clearance=clearance.name,
                          compartments=held)
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
    name: Storable = Field(min_length=3, max_length=120)
    classification: str = Field(min_length=3, max_length=20)
    default_reliability: str = Field(default="F", pattern="^[A-F]$")
    access_mode: Literal["PUBLIC_READ", "MEMBER"] = "PUBLIC_READ"
    poll_interval_s: int = Field(default=1800, ge=300, le=7 * 86400)
    jitter_pct: int = Field(default=25, ge=0, le=50)
    max_rps: float = Field(default=0.2, ge=0.05, le=1.0)
    #: The compartments the chat's source and everything it collects are filed under; the creator
    #: must hold each.
    compartments: list[str] = Field(default_factory=list, max_length=32)


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
    clearance, held = user_ceiling(conn, user.user_id)
    # Everything that needs no key and no network is refused here, before anything is queued: a
    # private invite link is a bearer join credential and queue rows are never deleted, so it must
    # never be written, and a typo is a cheap 400. Only the parsed reference is queued, never the
    # text typed.
    try:
        parsed = check_create_request(body.ref, body.access_mode,
                                      body.classification,
                                      compartments=body.compartments,
                                      held_compartments=held)
    except CollectionError as exc:
        raise _problem(exc) from None
    params = body.model_dump()
    params["ref"] = normal_reference(parsed)
    # Held at the label asked for. One that is no label, or above the caller, is held at their own
    # clearance and refused when it runs, in create's own words and order.
    try:
        label = (body.classification
                 if tlp_from_name(body.classification) <= clearance
                 else clearance.name)
    except AccessResolutionError:
        label = clearance.name
    return _act(conn, user, "TELEGRAM_RESOLVE", source_id=None,
                classification=label, params=params,
                adapters=adapters, factory=factory)


class JoinBody(BaseModel):
    acknowledge_overt: Literal[True]
    note: Storable = Field(min_length=10, max_length=500)


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
    clearance, held = user_ceiling(conn, user.user_id)
    return _act(conn, user, "TELEGRAM_JOIN", source_id=source_id,
                classification=_chat_label(conn, source_id, clearance.name, held),
                params={"note": body.note}, adapters=adapters, factory=factory)


class ReasonBody(BaseModel):
    reason: Storable = Field(min_length=5, max_length=500)


class RebindBody(BaseModel):
    persona_id: UUID
    reason: Storable = Field(min_length=5, max_length=500)


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
    clearance, held = user_ceiling(conn, user.user_id)
    return _act(conn, user, "TELEGRAM_REBIND", source_id=source_id,
                classification=_chat_label(conn, source_id, clearance.name, held),
                params={"persona_id": body.persona_id, "reason": body.reason},
                adapters=adapters, factory=factory)


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
    clearance, held = user_ceiling(conn, user.user_id)
    # The mark and the check run together, where the persona key is; act_problem says the mark
    # stood when the check refused.
    return _act(conn, user, "TELEGRAM_MARK_MEMBER", source_id=source_id,
                classification=_chat_label(conn, source_id, clearance.name, held),
                params={"reason": body.reason}, adapters=adapters,
                factory=factory)


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
    clearance, held = user_ceiling(conn, user.user_id)
    return _act(conn, user, "TELEGRAM_MEMBERSHIP", source_id=source_id,
                classification=_chat_label(conn, source_id, clearance.name, held),
                params={}, adapters=adapters, factory=factory)


def _set_active(source_id, body, user, conn, adapters, active: bool,
                sconn) -> dict:
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        # Written on a system connection: sources are read-only to the request role (0179).
        return _chats(sconn, adapters, None).set_active(
            source_id, active=active, reason=body.reason, actor_id=user.user_id,
            clearance=clearance.name, compartments=held)
    except CollectionError as exc:
        raise _problem(exc) from None


@router.post("/chats/{source_id}/deactivate", response_model=dict)
def stop_chat(
    source_id: UUID, body: ReasonBody,
    user: CurrentUser = Depends(require_global("source.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    sconn: psycopg.Connection = Depends(_CONFIG),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """Stop reading a chat. No persona act and no rate limit beyond the
    global one: stopping is always allowed."""
    return _set_active(source_id, body, user, conn, adapters, False, sconn)


@router.post("/chats/{source_id}/resume", response_model=dict)
def resume_chat(
    source_id: UUID, body: ReasonBody,
    user: CurrentUser = Depends(require_global("source.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    sconn: psycopg.Connection = Depends(_CONFIG),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """Read a stopped chat again. Its authority and its refusals decide
    whether it is read; a chat that became a supergroup is not resumed."""
    return _set_active(source_id, body, user, conn, adapters, True, sconn)
