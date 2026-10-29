"""Proof of possession for the first-run door.

`POST /setup/first-admin` gives whoever calls while `iam.app_user` is empty an account holding
SYS_ADMIN and SECURITY_OFFICER at RED, with its password and TOTP secret; on an internet-facing
stack that is a race the operator can lose. So the door needs `NOCTORNAL_SETUP_TOKEN` (at least
`MIN_TOKEN_CHARS`) in `X-Setup-Token`, compared in constant time over fixed-length digests, and a
miss is metered as a sign-in failure. Under `NOCTORNAL_ENV=production` with no token the route
answers 404 like an unknown path, and the first account is made from the server
(`scripts/bootstrap.py create-user`); outside production the door opens without a token and
honours one if set. Either way it opens only while the table is empty.

FastAPI reads and validates a request before any dependency runs, so a door closed inside the
route would answer differently from no door (a 422, 413, 405 or redirect). `ClosedSetupDoor`, pure
ASGI and innermost, answers the path in any method with an unknown path's 404 before anything is
read; `require_setup_door` keeps its own 404 as the backstop for an app built without it.
"""
from __future__ import annotations

import hashlib
import hmac
import os

from fastapi import Header, HTTPException, Request
from starlette.responses import JSONResponse

from noctornal_api.config import is_production
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import consume_on_failure

SETUP_TOKEN_ENV = "NOCTORNAL_SETUP_TOKEN"
SETUP_TOKEN_HEADER = "X-Setup-Token"

#: A token shorter than this is refused at a production boot (`config.py`),
#: because a four-letter token is a door with a lock that opens by asking.
#: `openssl rand -hex 32` is 64.
MIN_TOKEN_CHARS = 32


def configured_token() -> str | None:
    """The token this process was given, or None when there is none."""
    raw = os.environ.get(SETUP_TOKEN_ENV, "").strip()
    return raw or None


def _production() -> bool:
    return is_production()


def door_closed() -> bool:
    """True when this deployment offers no web first-run at all: production
    with no token configured."""
    return _production() and configured_token() is None


def token_required() -> bool:
    """True when the caller must present a token to use the door."""
    return configured_token() is not None


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).digest()


def matches(presented: str | None) -> bool:
    """Whether `presented` is the configured token. False when none is
    configured and when nothing was presented: there is no token a caller
    could be holding."""
    expected = configured_token()
    if expected is None or not presented:
        return False
    return hmac.compare_digest(_digest(presented), _digest(expected))


class ClosedSetupDoor:
    """While `door_closed()`, answer the first-run path as an unknown path is answered, whatever
    the method, headers or body, without reading the request.

    `path` comes from the router, so the gate cannot drift from the route it hides; the path with
    a trailing slash is covered too, since the router would redirect it, which an unknown path
    never does. `door_closed()` is read per request, so a token set or unset since is honoured.
    """

    def __init__(self, app, path: str):
        self.app = app
        bare = path.rstrip("/")
        self._paths = frozenset({bare, bare + "/"})

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") == "http" and door_closed() \
                and _route_path(scope) in self._paths:
            # The default handler's own body and type, so the answer is the
            # one an unknown path gives byte for byte; the outer middleware
            # dresses both alike.
            await JSONResponse({"detail": "Not Found"},
                               status_code=404)(scope, receive, send)
            return
        await self.app(scope, receive, send)


def _route_path(scope) -> str:
    """The path the router matches on: the request path without the
    deployment's `root_path`, as Starlette computes it."""
    path = scope.get("path", "")
    root = scope.get("root_path", "")
    if root and path.startswith(root):
        return path[len(root):]
    return path


def install_closed_setup_door(app, path: str) -> None:
    """Register `ClosedSetupDoor` INNERMOST (call it before every other
    `add_middleware`), so the limiter still counts the request and the
    security headers still dress the 404 exactly as they dress an unknown
    path's."""
    app.add_middleware(ClosedSetupDoor, path=path)


def require_setup_door(
    request: Request,
    x_setup_token: str | None = Header(default=None, alias=SETUP_TOKEN_HEADER,
                                       max_length=512),
) -> None:
    """The dependency in front of `POST /setup/first-admin`.

    It runs after the body has been read as JSON but before it is
    validated against the schema, so a caller without the token learns
    nothing from a 422 about the fields. (A body that is not JSON at all
    is refused by FastAPI before any dependency, so that one 422 does not
    depend on the token; the token is not what it reveals.)"""
    if door_closed():
        # The same answer an unknown path gets (Starlette's own, not a
        # problem document). `ClosedSetupDoor` answers first for every
        # request shape; this is the backstop for an app built without it.
        raise HTTPException(status_code=404)
    if not token_required():
        return
    if matches(x_setup_token):
        return
    consume_on_failure(request, "auth.login_failed")
    raise Problem(403, "Forbidden",
                  f"the {SETUP_TOKEN_HEADER} header must carry this "
                  f"deployment's setup token")
