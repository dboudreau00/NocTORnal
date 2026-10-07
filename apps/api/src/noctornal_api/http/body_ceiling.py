"""A request-body ceiling on every route, before anything reads the body (http_ui-005, 2026-10-03).

FastAPI reads and parses a body BEFORE it resolves a single dependency,
so on every route with a Pydantic body (sign-in, first-run setup, case
creation, approvals and about 150 more) the whole request was held in
memory before authentication, validation or the rate limiter's endpoint
meter could refuse it, and the proxy sets no limit either (Caddyfile).
One unauthenticated request with a multi-gigabyte JSON body made the one
API process allocate all of it; the review measured 100 MiB pulled from
the socket before a 422. The caps in `limits.py` covered only the routes
that opted in (`body_cap` + `BodyCappedRoute`, `read_body_capped`).

This middleware is the default for everything else. It wraps the ASGI
`receive` the route reads through and refuses with the same 413 as
`limits.body_too_large` once the body passes the route's ceiling:

- a route marked `body_cap` (a multipart upload behind
  `BodyCappedRoute`) keeps its own cap, enforced here as well;
- a route marked `raise_body_ceiling` gets the larger ceiling it names,
  for the few JSON bodies that are legitimately big (a 1,000,000
  character paste, a 20,000 node layout);
- a route marked `own_body_cap` reads its body itself, after it has
  authenticated the caller, through `read_body_capped` against a cap only
  it knows (the ingest submit, per key); it is left alone;
- everything else gets `DEFAULT_BODY_CEILING`.

The route is known by the time its handler first asks for the body:
routing has put its endpoint in the shared scope. A declared
Content-Length over the ceiling is refused before a byte is read; a body
with no length, or a lying one, is counted chunk by chunk. A refusal
replaces whatever the application would have answered (FastAPI turns an
exception raised under its body parser into a 400), so the caller always
reads the 413 with the cap in it. Pure ASGI rather than
`@app.middleware("http")`, because the body must never pass through a
`Request` that buffers it.

The same wrapper refuses a JSON body that carries a NUL character
(http_ui-014, 2026-10-03) with a 422, once the body is complete and
before the route parses it: Postgres cannot store U+0000 in text or
jsonb, and several routes answered one with a 500 and a logged
traceback. Routes that cap their own body are left to their own rules
here too (the ingest dead-letters what it cannot parse).

The same goes for a lone surrogate escape (`\\ud800` to `\\udfff` not
paired with its other half), refused with a 422 (2026-10-07):
it decodes to a string no UTF-8 encoder will take, so Postgres' driver
raised `UnicodeEncodeError` and an unconstrained text field answered 500.

And a `body_cap` route is refused with its own 401 before a byte is read
when the request presents no session credential at all (2026-10-07). FastAPI parses a
multipart form before it resolves a
single dependency and Starlette spools the parse to disk, so an upload
route with a 256 MiB cap wrote up to 256 MiB for a caller that was never
going to be let in, and nothing in front of the API bounds a body. This
refuses only a request that presents NOTHING: a junk bearer or cookie
still reads as it always did and is judged by the route, because telling a
live session from a junk one takes the database and this layer is
deliberately database-free (docs/17 records the residual). A route whose
caller presents its credential in the body (the one-shot ticket of a
download) is marked `credential_in_body` and is left alone.
"""
from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable

from starlette.requests import Request

from noctornal_api.http.deps import NO_SESSION_DETAIL, presents_session_credential
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import body_too_large

#: The ceiling for a route that declares nothing larger. Every JSON and
#: form body this console sends is far below it.
DEFAULT_BODY_CEILING = 1024 * 1024

#: A JSON string escape for U+0000: `\u0000` after an even run of
#: backslashes, so `\\u0000` (a literal backslash, then text) is not one.
#: JSON can carry a NUL no other way; a raw 0x00 byte is not valid JSON.
_NUL_ESCAPE = re.compile(rb"(?<!\\)(?:\\\\)*\\u0000")

#: The 422 for a NUL in a JSON body (http_ui-014, 2026-10-03). Postgres
#: text and jsonb cannot hold U+0000, so no route can store one, and
#: until this check several answered the attempt with a 500 and a
#: traceback (assumptions, curation sets, the node pre-check).
NUL_DETAIL = ("a text field contains a NUL character (U+0000), which "
              "cannot be stored; remove it and send the request again")

#: A JSON escape for a surrogate code unit (`\uD800` to `\uDFFF`), after an
#: even run of backslashes. Only a screen: a properly paired high and low
#: escape is how JSON spells a character outside the BMP and is fine, so a
#: body that matches is parsed and its strings tried (`_lone_surrogate`).
_SURROGATE_ESCAPE = re.compile(rb"(?<!\\)(?:\\\\)*\\u[dD][89a-fA-F][0-9a-fA-F]{2}")

#: The 422 for text that is not text (2026-10-07). An unpaired
#: surrogate decodes to a string no UTF-8 encoder accepts, so it can be
#: neither stored nor logged; paired escapes are accepted.
SURROGATE_DETAIL = ("a text field contains an unpaired surrogate escape "
                    "(a lone \\ud800 to \\udfff), which is not text and "
                    "cannot be stored; remove it and send the request again")


def _lone_surrogate(body: bytes) -> bool:
    """Whether `body` is JSON with a lone surrogate in any string or key.
    Anything that is not readable JSON is not this check's to judge: the
    route answers it as it always has."""
    if not _SURROGATE_ESCAPE.search(body):
        return False
    try:
        json.dumps(json.loads(body), ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        return True
    except (ValueError, RecursionError):
        return False
    return False


def _is_json(scope) -> bool:
    for name, value in scope.get("headers") or ():
        if name == b"content-type":
            kind = value.split(b";", 1)[0].strip().lower()
            return kind == b"application/json" or (
                kind.startswith(b"application/") and kind.endswith(b"+json"))
    return False

_CEILING_ATTR = "__body_ceiling__"
_OWN_ATTR = "__own_body_cap__"
#: `limits.body_cap`'s marker, read here so a route's own cap holds even
#: where the router class would not enforce it.
_BODY_CAP_ATTR = "__body_cap__"
_BODY_CREDENTIAL_ATTR = "__body_credential__"


def raise_body_ceiling(cap: int, *, what: str):
    """Give one JSON route a ceiling above the default."""
    def mark(endpoint):
        setattr(endpoint, _CEILING_ATTR, (cap, what))
        return endpoint
    return mark


def own_body_cap(endpoint):
    """Mark a route that reads its own body through `read_body_capped`
    after authenticating, so the ceiling here does not apply to it."""
    setattr(endpoint, _OWN_ATTR, True)
    return endpoint


def credential_in_body(endpoint):
    """Mark a `body_cap` route whose caller may present its credential in
    the BODY (a one-shot ticket in a form field, on the sample origin where
    no session exists), so the check for a header or cookie credential
    before the body is read does not apply to it. The body is a few
    hundred bytes, so there is nothing to spool."""
    setattr(endpoint, _BODY_CREDENTIAL_ATTR, True)
    return endpoint


def _unauthenticated_upload(scope) -> bool:
    """True for a request to a `body_cap` route that presents no session
    credential, on a route that takes none from its body."""
    endpoint = scope.get("endpoint")
    if getattr(endpoint, _BODY_CAP_ATTR, None) is None \
            or getattr(endpoint, _BODY_CREDENTIAL_ATTR, False):
        return False
    return not presents_session_credential(Request(scope))


def ceiling_for(endpoint) -> tuple[int, str] | None:
    """(cap, what) for the route whose endpoint this is, or None for a
    route that caps its own body."""
    if endpoint is not None and getattr(endpoint, _OWN_ATTR, False):
        return None
    marker = getattr(endpoint, _BODY_CAP_ATTR, None) or getattr(
        endpoint, _CEILING_ATTR, None)
    if marker is not None:
        cap_of, what = marker
        return (cap_of() if callable(cap_of) else cap_of), what
    return DEFAULT_BODY_CEILING, "a request body"


def _declared(scope) -> int | None:
    for name, value in scope.get("headers") or ():
        if name == b"content-length":
            try:
                length = int(value)
            except ValueError:
                return None
            return length if length >= 0 else None
    return None


async def _send_problem(send, problem: Problem) -> None:
    from noctornal_api.http.errors import problem_response
    response = problem_response(problem.status, problem.title, problem.detail,
                                problem.type, problem.headers)
    await send({"type": "http.response.start", "status": response.status_code,
                "headers": response.raw_headers})
    await send({"type": "http.response.body", "body": response.body})


class BodyCeilingMiddleware:
    """See the module docstring."""

    def __init__(self, app: Callable[..., Awaitable[None]]):
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        refused: list[Problem] = []
        started = False
        total = 0
        limit: list[tuple[int, str] | None] = []
        # The JSON body, kept (it is under the ceiling, and the parser
        # holds it whole anyway) so the NUL check reads it once complete,
        # whatever the chunk boundaries were (http_ui-014).
        seen = bytearray() if _is_json(scope) else None

        async def capped_receive() -> dict:
            nonlocal total
            if not limit:
                limit.append(ceiling_for(scope.get("endpoint")))
                ceiling = limit[0]
                declared = _declared(scope)
                if ceiling is not None and declared is not None \
                        and declared > ceiling[0]:
                    refused.append(body_too_large(ceiling[0], ceiling[1],
                                                  declared=declared))
                    raise refused[0]
                if ceiling is not None and _unauthenticated_upload(scope):
                    refused.append(Problem(401, "Unauthenticated", NO_SESSION_DETAIL))
                    raise refused[0]
            message = await receive()
            ceiling = limit[0]
            if ceiling is not None and message.get("type") == "http.request":
                chunk = message.get("body", b"")
                total += len(chunk)
                if total > ceiling[0]:
                    if not refused:
                        refused.append(body_too_large(ceiling[0], ceiling[1]))
                    raise refused[0]
                if seen is not None:
                    seen.extend(chunk)
                    if not message.get("more_body", False):
                        if _NUL_ESCAPE.search(seen):
                            refused.append(Problem(422, "Validation failed", NUL_DETAIL))
                            raise refused[0]
                        if _lone_surrogate(seen):
                            refused.append(Problem(422, "Validation failed",
                                                   SURROGATE_DETAIL))
                            raise refused[0]
            return message

        async def guarded_send(message: dict) -> None:
            nonlocal started
            if refused:
                if message.get("type") == "http.response.start" and not started:
                    started = True
                    await _send_problem(send, refused[0])
                return
            if message.get("type") == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, capped_receive, guarded_send)
        except Exception:
            if refused and not started:
                await _send_problem(send, refused[0])
                return
            raise


def install_body_ceiling(app) -> None:
    """Register the ceiling INNERMOST of the middleware, so the limiter
    still counts the request and the security headers still dress the
    413 on the way out."""
    app.add_middleware(BodyCeilingMiddleware)
