"""Proof of possession for the first-run door (http_ui-010 and infra-3, 2026-10-03).

`POST /setup/first-admin` creates an account holding SYS_ADMIN,
SECURITY_OFFICER, CASE_OWNER and ANALYST at RED clearance for whoever
calls it while `iam.app_user` is empty, and hands back the password and
the TOTP secret, so there is no second factor to stop the caller. The
emptiness of the table is a sound gate AFTER the first account exists.
Before it, on an internet-facing stack, the gate is a race: Caddy starts
publishing 80 and 443 as soon as the API container is up, the hostname is
in certificate-transparency logs within seconds of issuance, `GET
/setup/status` says the instant `needs_setup` is true and the route path is
public in this repository. The first caller to arrive owned the
deployment's administration and the officer role that reviews break-glass.

So the door now needs a secret only the operator holds:

- `NOCTORNAL_SETUP_TOKEN` is read from the environment (secrets.env in the
  production stack), at least `MIN_TOKEN_CHARS` characters, and is
  presented in the `X-Setup-Token` header. The comparison is constant-time
  and made over fixed-length digests, so neither the value nor its length
  is learnable from the timing, and a wrong or missing token is metered
  against the sign-in failure meter like any other guess.
- Under `NOCTORNAL_ENV=production` with NO token configured the route does
  not exist: it answers 404, exactly as an unknown path does, and the
  first account is made from the server (`scripts/bootstrap.py
  create-user`). That is the safe default for a deployment whose operator
  never set one, and it is the fail-closed reading of "unknown caller".
- Outside production the door stays open without a token, as it always was
  (a laptop, CI and the e2e suite have no secrets file and no internet
  address), and a token set there is honoured all the same.
- The token is one-time in the only sense that matters: it opens the door
  only while the table is empty, and the door answers 409 for ever after
  (`iam_admin.create_first_admin`). The README says to remove it from
  secrets.env once the first account exists.

`GET /setup/status` reports `needs_setup` as the console should read it:
true only while the door can actually be used, so a closed door never
invites the first-run card. It adds `setup_token_required` so the card
knows to ask for the token.

## A closed door answers before the request is read (2026-10-03)

The first version closed the door inside the route's own dependency, and
FastAPI reads and parses the body, and validates every parameter, BEFORE a
dependency runs. So a closed door answered 404 only to a request that was
well formed: invalid JSON got a 422 problem document, an `X-Setup-Token`
header over 512 characters got a 422, a body over the 1 MiB ceiling got a
413, a GET got a 405 and a trailing slash got a redirect, every one of
which an unknown path answers with the plain 404. A scanner could tell the
closed door from no door, which the README and this module both claim it
cannot. `ClosedSetupDoor` is the fix: pure ASGI, innermost of the
middleware, it answers the path itself, in any method, with the body of an
unknown path's 404, before anything is read, so no request shape differs.
`require_setup_door` keeps its own 404 as the backstop for an app built
without the middleware.
"""
from __future__ import annotations

import hashlib
import hmac
import os

from fastapi import Header, HTTPException, Request
from starlette.responses import JSONResponse

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
    return os.environ.get("NOCTORNAL_ENV", "").strip().lower() == "production"


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
    """While `door_closed()`, answer the first-run path as an unknown path
    is answered, whatever the method, the headers or the body, and without
    reading the request (see the module docstring).

    `path` is the route's own path, taken from the router by the caller,
    so the gate cannot drift from the route it hides; the same path with a
    trailing slash is covered too, because the router would redirect it to
    the real route and a redirect is an answer an unknown path never gives.
    `door_closed()` is read per request, as the dependency read it, so a
    token set or unset between requests (a test, a restart) is honoured.
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
