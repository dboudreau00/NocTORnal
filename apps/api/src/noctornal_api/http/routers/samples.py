"""Sample handling over HTTP (Phase 8, docs/11, invariant 10).

COUNSEL MUST REVIEW A DEPLOYMENT OF THIS. See `samples.py` and the README
warning block; the short version is that a store of attacker-supplied
binaries will eventually receive material whose possession alone is an
offence, and the code being correct does not make the deployment lawful.

## Metadata renders here. Bytes do not.

Every endpoint in this file returns JSON about a sample -- hashes, file
type, entropy, analysis findings, custody. That is invariant 10's first
half, and it is why the UI can show a sample at all.

The second half is that `/download` returns the encrypted archive and is
the ONLY endpoint that touches sample bytes, and it refuses unless THIS
PROCESS is configured as the sample origin -- `NOCTORNAL_PUBLIC_ORIGIN`
equal to `NOCTORNAL_SAMPLE_ORIGIN`, which must itself differ from the
application origin in `NOCTORNAL_BASE_URL` (`samples.origin_split()` is
the one decision, and the readiness register reads the same one). The
check is in the service so it cannot be skipped by a second caller, and
the response headers are the belt to those braces: `application/octet-
stream`, `Content-Disposition: attachment`, `nosniff`, and a CSP of
`sandbox` so that even if something upstream serves this as HTML the
browser will not execute it.

Until 2026-09-09 the route derived "where the request arrived" from
`request.url`, which is the Host header. That is a value the client
sends, so the check granted on it; and because the console's CSP was
`connect-src 'self'`, the only way the Lab pane could download at all was
for the sample origin to BE the application origin, which is the
configuration the invariant forbids. Now the console fetches the sample
origin directly (app.py names it in `connect-src`, and the sample process
answers the cross-origin request for the application origin alone), and
the verdict comes from configuration.

**When `NOCTORNAL_SAMPLE_ORIGIN` is unset the control is OFF.** Every
download refuses on every process, `GET /samples/policy` reports the
problem in `sample_origin_problem`, and `GET /admin/readiness` fails the
`sample_origin_configured` check with the action. No document may say
invariant 10 holds for such a deployment; the code does not back it.

## The credential that crosses to the sample origin (0061)

Because a `__Host-` cookie cannot reach a second origin -- the point of
the split -- the console used to send the token the login response handed
it, as a Bearer, to the sample process. `POST
/samples/{id}/download-ticket` replaced that on 2026-09-10: minted HERE,
on the application origin, under the ordinary cookie session and its CSRF
double-submit, it authorises ONE download of ONE sample within a minute
and is spent by the first redemption -- which re-reads the holder's
account and their live clearance before serving, so an authority
withdrawn inside that minute bites. The download takes it in the form
body, and that is now the only thing the console presents there. The
Bearer path is unchanged and still works, for callers that are not the
console; nothing in the shipped client sends one.

That body is also why the download is metered on the peer address
(`sample.download` in the limit catalogue, applied by `_meter_download`):
a credential in the body means this process cannot tell an authorised
caller from a stranger until it has looked one up, and every look-up that
fails used to append to the hash-chained audit log.

## Two permissions that do not imply each other

`sample.read` is case-side: an analyst may see that a sample exists and
what the lab found. `sample.download` is lab-side and step-up gated: it is
the one action in this system that puts working malware on somebody's
disk. `MALWARE_ANALYST` holds the second and deliberately holds no case
access at all.
"""
from __future__ import annotations

import hashlib
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, File, Form, Request, Response, UploadFile
from pydantic import BaseModel, Field

from noctornal_api.http.deps import (
    SESSION_COOKIE,
    CurrentUser,
    authorize_object,
    check_writable_labels,
    current_user,
    get_conn,
    require_global,
    require_step_up,
    session_token,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import (
    BodyCappedRoute,
    body_cap,
    client_ip,
    enforce,
    rate_limit,
)
from noctornal_api.config import SAMPLE_CAP_ENV, cap_is_declared
from noctornal_api.ratelimit import ip_subject
from noctornal_api.samples import (
    MAX_SAMPLE_BYTES,
    PolicyNotDeclared,
    Sample,
    SampleError,
    SampleService,
    origin_split,
    policy_declared,
)

# `route_class=BodyCappedRoute` is what makes the `@body_cap` marker on
# `submit` do anything (routers/evidence.py, which opted in first,
# explains the mechanism): the class wraps the ASGI receive that
# FastAPI's multipart parser reads through, and only for endpoints
# carrying the marker. Until 2026-09-09 the cap here was a private
# `_read_capped` that read the upload in chunks AFTER the parser had
# spooled the whole body to a temporary file: it bounded this process's
# memory, and the bytes had all arrived.
router = APIRouter(prefix="/samples", tags=["samples"],
                   route_class=BodyCappedRoute)


def _svc(conn: psycopg.Connection) -> SampleService:
    from noctornal_api.samples import SampleStorage
    return SampleService(conn, SampleStorage())


def _ticket_svc(conn: psycopg.Connection) -> SampleService:
    """The service with NO storage, for the two steps that decide who may
    have bytes without ever touching any.

    `SampleStorage()` raises when the bucket is unconfigured, so building
    one here would make a decision about ACCESS fail on the absence of a
    credential it would never use -- and the mint runs on the application
    process, which is not the one that serves malware. Neither minting
    nor redeeming reads a sample; the route that serves one builds the
    store for itself, a line later.
    """
    return SampleService(conn)


#: The gate the download has always carried, hoisted so the ticket mint
#: states the same one and so the download can apply it by CALL rather
#: than by `Depends`. FastAPI resolves every declared dependency, so a
#: route that authenticates two ways cannot express either of them as a
#: dependency -- see `download`.
#:
#: The key is spelled out rather than taken from `samples.
#: DOWNLOAD_PERMISSION`, which is the same string and is what the
#: redemption re-reads on the other origin: `test_ui_invariants` pins this
#: line literally, so that "the mint states the download's own gate" is
#: checked against source text a rename cannot quietly satisfy. The two
#: spellings are held equal by a test rather than by an import.
_REQUIRE_DOWNLOAD = require_global("sample.download")

#: A ticket is 43 URL-safe characters, so 2 KB of form body is room for it
#: and nothing worth having. The download parses a body now, and a route
#: that parses a body bounds one: without this the sample origin would
#: buffer whatever an unauthenticated caller sent before deciding it was
#: not a ticket.
_TICKET_BODY_CAP = 2 * 1024


def _ip_hash(request: Request) -> bytes | None:
    """The peer address, hashed, for the ticket row and its audit.

    `client_ip` rather than `request.client.host`, for the reason
    `routers/auth.py` records against the same three lines: behind a
    proxy the latter is the load balancer, so every event was attributed
    to the address of the thing in front of the application.
    """
    ip = client_ip(request)
    return hashlib.sha256(ip.encode()).digest() if ip else None


def _download_url(sample_origin: str, sample_id: UUID) -> str:
    """Where the ticket is to be redeemed.

    `API_PREFIX` lives in `http/app.py`, which imports this module, so the
    import is deferred to call time -- the same shape `_svc` uses for
    `SampleStorage`. Built from it rather than written out, because the
    URL handed to the console must be a path this deployment actually
    serves: `app._DOWNLOAD_PATH`, the pattern the sample process's
    allow-list and its CORS answer both match on, is built from the same
    constant.
    """
    from noctornal_api.http.app import API_PREFIX
    return f"{sample_origin}{API_PREFIX}/samples/{sample_id}/download"


class SampleOut(BaseModel):
    id: str
    case_id: str | None
    sha256: str
    sha1: str | None
    md5: str | None
    original_filename: str | None
    byte_size: int
    state: str
    reject_reason: str | None
    file_type: str | None
    entropy: float | None
    #: What triage could NOT establish, and why. A NULL imphash reads as
    #: "no imports"; a recorded gap reads as "nobody looked".
    triage_gaps: list
    submitted_by: str
    submitted_at: str
    source_note: str | None
    assigned_to: str | None
    classification: str


def _out(s: Sample) -> SampleOut:
    return SampleOut(
        id=str(s.id), case_id=str(s.case_id) if s.case_id else None,
        sha256=s.sha256, sha1=s.sha1, md5=s.md5,
        original_filename=s.original_filename, byte_size=s.byte_size,
        state=s.state, reject_reason=s.reject_reason, file_type=s.file_type,
        entropy=s.entropy, triage_gaps=s.triage_gaps,
        submitted_by=str(s.submitted_by),
        submitted_at=s.submitted_at.isoformat(), source_note=s.source_note,
        assigned_to=str(s.assigned_to) if s.assigned_to else None,
        classification=s.classification,
    )


@router.get("/policy", response_model=dict)
def policy_status(_: CurrentUser = Depends(current_user)) -> dict:
    """Whether an operator has declared a prohibited-content policy, and
    whether a separate sample origin is configured -- and which one.

    Surfaced rather than buried so that "sample submission is refused" has
    a discoverable cause. Returns the operator's own reference, which is
    the point of asking for a reference rather than a boolean.

    `sample_origin` is the origin the console must fetch a download from,
    or null; the Lab pane builds its download URL from it, because the
    console is served from the application origin and the bytes are not.
    `sample_origin_configured` is true only when the split is USABLE: set,
    an origin, and not a second name for the application's. A value that
    is set but unusable used to read as "configured" here while every
    download refused, and `sample_origin_problem` now carries the reason
    instead of the console guessing at one.
    """
    declared, detail = policy_declared()
    split = origin_split()
    usable = split.split_problem is None
    return {
        "policy_declared": declared,
        "policy_reference": detail if declared else None,
        "detail": None if declared else detail,
        "sample_origin_configured": usable,
        "sample_origin": split.sample if usable else None,
        "sample_origin_problem": split.split_problem,
        # The cap `submit` enforces on THIS process, for the picker.
        "max_sample_bytes": MAX_SAMPLE_BYTES,
        "max_sample_bytes_declared": cap_is_declared(SAMPLE_CAP_ENV),
        "counsel_review_required": True,
        "notice": (
            "Counsel must review this deployment before it is used in any "
            "absolute sense. A store of attacker-supplied binaries will "
            "eventually receive material whose possession alone is an "
            "offence, and the handling rules differ by jurisdiction. This "
            "software records a declaration; it cannot verify one."
        ),
    }


@router.post("", response_model=SampleOut, status_code=201,
             dependencies=[Depends(rate_limit("evidence.ingest"))])
@body_cap(lambda: MAX_SAMPLE_BYTES, what="a sample submission")
async def submit(
    request: Request,
    file: UploadFile = File(...),
    case_id: UUID | None = Form(None),
    source_note: str | None = Form(None),
    classification: str = Form("AMBER"),
    compartments: str = Form(""),
    user: CurrentUser = Depends(require_global("sample.submit")),
    conn: psycopg.Connection = Depends(get_conn),
) -> SampleOut:
    """Land a sample in QUARANTINE. Nothing reaches the RE queue until
    triage has run, and nothing is accepted at all until a
    prohibited-content policy has been declared.

    The request body is capped at `MAX_SAMPLE_BYTES`, enforced by
    `BodyCappedRoute` on the bytes as they arrive: a declared length over
    the cap is refused before a byte is read, a chunked body on the chunk
    that crosses, and the 413 names the cap. Nothing below runs for a
    refused upload. Until 2026-09-09 the cap was a chunked read of the
    upload in this router, which ran after FastAPI's multipart parser had
    spooled the whole body to a temporary file.

    `sample.submit` is a GLOBAL permission — `require_global` resolves the
    verb, the active account and step-up freshness, and knows nothing about
    a case. So a caller holding it could previously attach a sample to ANY
    case id, including one the access gate would answer 404 for: a write
    into a case file they cannot see, which then carries that case's labels
    and appears in its report. `authorize_object` closes that, and it is
    the same five-part decision every other case-scoped write makes.

    `compartments` exists at all now because the form had no field for it,
    so every sample landed with `'{}'` whatever its case required. The
    service unions the case's in regardless; this is for the case where the
    SAMPLE is more restricted than the case it came from, which is the
    normal direction for a sample carrying a source's fingerprints.
    """
    parsed = frozenset(c.strip() for c in compartments.split(",") if c.strip())
    # Refuse to author what the caller could not read back. Without this a
    # holder of `sample.submit` — CASE_OWNER, ANALYST and REVIEWER all hold
    # it — could land a RED sample from an AMBER account: a row they
    # created, cannot see, and cannot correct. It also closes the first
    # step of the original critical, which began "submit at RED, then
    # download it".
    #
    # Applied on BOTH paths. `authorize_object` covers the case-attached
    # one and composes the case's labels in, but a sample with no case
    # never reaches it, and an unattached sample is exactly where an
    # over-labelled row would sit unnoticed.
    check_writable_labels(conn, user, classification=classification,
                          compartments=parsed)
    if case_id is not None:
        authorize_object(conn, user, case_id=case_id,
                         permission_key="sample.submit",
                         classification=classification, compartments=parsed)
    # Bounded before it starts: the route class refused anything over the
    # cap at the receive. The service re-checks the length as its own
    # precondition.
    data = await file.read()
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        return _out(_svc(conn).submit(
            data, submitted_by=user.user_id, case_id=case_id,
            # The filename is stored for the record and is NEVER used as a
            # path component or rendered unescaped.
            original_filename=file.filename, source_note=source_note,
            classification=classification, compartments=parsed,
            # Only for how much the duplicate refusal may say: uploading a
            # hash you suspect and reading the error back is a cheap probe
            # for "is anybody else working this intrusion".
            visible_to_clearance=clearance.name,
            visible_to_compartments=held))
    except PolicyNotDeclared as exc:
        # 451: the refusal is legal, not technical, and a 400 would send
        # somebody looking at their upload.
        raise Problem(451, "Unavailable for legal reasons", safe_detail(exc)) from exc
    except SampleError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc


@router.get("", response_model=dict)
def queue(
    user: CurrentUser = Depends(require_global("sample.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The RE queue, filtered by the caller's own clearance and compartments
    COMPOSED with each sample's case.

    Both directions matter and the service handles both: a sample can be
    classified above its case, so the case gate alone would leak its
    existence; and it can sit below its case, because `lab.sample` has no
    classification floor trigger, so the sample's own labels alone would
    leak the case's.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    rows = _svc(conn).queue(clearance=clearance.name, compartments=compartments)
    return {"samples": [_out(s).model_dump(mode="json") for s in rows]}


@router.get("/{sample_id}", response_model=dict)
def detail(
    sample_id: UUID,
    user: CurrentUser = Depends(require_global("sample.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """One sample's metadata, its findings and its custody ledger.

    The label check moved INTO the service as `visible()` (F19). It used to
    live here, comparing the sample's own classification and compartments
    and nothing else — so a sample submitted into a RED compartmented case
    at the router's `AMBER` default was readable by anyone with AMBER
    clearance, because `lab.sample` has no `enforce_tlp_floor` trigger to
    stop the row existing at AMBER in the first place.

    Doing it in the service means the composition is written once and a
    second caller cannot skip it. That is not hypothetical: `download()` is
    the caller that skipped it.
    """
    svc = _svc(conn)
    clearance, compartments = user_ceiling(conn, user.user_id)
    # 404 rather than 403: a status code must not be an existence oracle
    # for a compartmented case (deps.py rule 2).
    sample = svc.visible(sample_id, clearance=clearance.name,
                         compartments=compartments)
    if sample is None:
        raise Problem(404, "Not found", "no such sample")
    return {"sample": _out(sample).model_dump(mode="json"),
            "analyses": svc.analyses(sample_id),
            "detonations": svc.detonations(sample_id),
            "custody": svc.custody(sample_id)}


class DownloadTicketOut(BaseModel):
    #: Returned exactly once. The row holds its SHA-256 and nothing else,
    #: so this string exists in this response and in the page that asked
    #: for it, and nowhere a log, a backup or a Referer can reach.
    ticket: str
    expires_at: str
    #: Absolute, on the SAMPLE origin: the console must not have to
    #: assemble it, because assembling it from `location.origin` is how
    #: the Lab pane came to fetch the application origin in the first
    #: place -- the one place the download is guaranteed to refuse.
    download_url: str


@router.post("/{sample_id}/download-ticket", response_model=DownloadTicketOut,
             status_code=201)
def mint_download_ticket(
    sample_id: UUID,
    request: Request,
    user: CurrentUser = Depends(_REQUIRE_DOWNLOAD),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> DownloadTicketOut:
    """A one-shot, sixty-second authority to download ONE sample from the
    sample origin.

    ## Why this exists

    `__Host-` cookies are `Secure`, `Path=/`, no `Domain`,
    `SameSite=strict`: they cannot reach the sample origin, and that is
    the POINT of the split rather than a limitation of it. So the console
    forced the token from the login response there as a Bearer -- the
    session credential itself, held in page memory, posted to a second
    origin, on the one path that puts working malware on a disk. This
    endpoint is what lets that stop: the credential that crosses is good
    for one sample, one redemption and sixty seconds, and buys the
    archive the analyst was already downloading rather than the case file.

    ## Why it is a POST, and what the CSRF header does and does not buy

    It is authenticated by the ORDINARY session dependency, which means a
    caller presenting the cookie must also send the `x-csrf-token`
    double-submit (`deps.session_token`), and only an unsafe method
    demands it -- a GET would be exempt, which is the first reason this
    mint is a POST. The second is that a GET minting a credential is one
    a prefetcher, a link scanner or a chat unfurl can trigger.

    The double-submit is what a page on ANOTHER origin cannot satisfy: it
    can make the browser send the cookie, but CORS will not let it set a
    custom header on a request that carries one, and `SameSite=strict`
    stops the cookie travelling in the first place. Stated precisely
    because the tempting shorter claim is false: a script injected into
    the console's OWN origin reads the CSRF cookie like any other script
    and can forge the header. Nothing in a browser stops that, which is
    exactly why what this hands back is scoped to one sample and expires
    in a minute instead of being the session token it replaces.

    ## The decision is the download's, not a second copy of it

    `SampleService.issue_download_ticket` runs the same
    `_downloadable` check `download()` runs -- clearance stated, sample
    readable at it with its case's labels composed in, compartments held,
    not REJECTED, data key present -- so a ticket can never be minted for
    a sample the caller could not have downloaded directly. It also
    refuses on this process being the sample origin, and on the split
    being unusable at all.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    try:
        ticket = _ticket_svc(conn).issue_download_ticket(
            sample_id, actor_id=user.user_id, clearance=clearance.name,
            compartments=compartments,
            # Which session asked, for the audit chain. Recorded, never
            # re-checked at redemption: see 0061.
            session_id=user.session_id, ip_hash=_ip_hash(request))
    except SampleError as exc:
        if "no such sample" in str(exc):
            # 404, and the same 404 `detail()` gives: "this sample exists
            # but is not yours" is itself a disclosure about a
            # compartmented case.
            raise Problem(404, "Not found", "no such sample") from exc
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    # Not None: every split whose `sample` is unset was refused above,
    # by the service, before a row was written.
    sample_origin = origin_split().sample or ""
    return DownloadTicketOut(
        ticket=ticket.raw,
        expires_at=ticket.expires_at.isoformat(),
        download_url=_download_url(sample_origin, sample_id))


def _meter_download(request: Request, response: Response) -> None:
    """Meter the download on the PEER ADDRESS, before anything else runs.

    The subject is the address because it is the only one that exists at
    this point: since 0061 the credential may be a ticket in the body, so
    nothing is known about the caller until a ticket has been looked up,
    and the caller cannot mint an address the way `credential_subject`
    warns they can mint a token.

    Declared as a route-level dependency rather than a handler parameter
    so it is solved FIRST -- FastAPI inserts these at the front of the
    dependant -- and declared with no connection of its own, which is the
    whole reason it is written out here instead of using
    `limits.rate_limit("sample.download")`. That factory's IP branch takes
    `Depends(get_conn)` so it can audit a denial, and taking it would open
    a database connection for every request to this route including the
    tokenless ones `_credential_presented` exists to refuse without one --
    `db.connect()` is a real connect, not a pool checkout. The trade is
    stated rather than hidden: a denial here is logged by `enforce` and
    never written to `audit.event`. That is the right way round on this
    particular route, where the whole defect being closed was an
    unauthenticated caller's ability to cause audit writes.
    """
    enforce(request, response, "sample.download",
            ip_subject(client_ip(request)))


def _credential_presented(request: Request) -> None:
    """Refuse a request that presents nothing, before a connection opens.

    `deps.session_token` is declared ahead of `get_conn` on purpose, and
    says why: a tokenless request must 401 without ever opening a database
    connection, so an unauthenticated flood costs no connections and an
    outage still answers 401. The ticket path would have quietly ended
    that -- a ticket travels in the BODY, so this route can no longer
    decide from headers alone, and `get_conn` would resolve for every
    caller including one presenting nothing at all.

    So the cheap question is asked first and from the headers only: is
    there a credential of ANY kind here? A body counts as one without
    being read, because reading it here to look for the ticket would
    parse it twice. A caller who sends junk in a body therefore costs a
    connection -- exactly as one who sends junk in `Authorization`
    always has.
    """
    if (request.headers.get("authorization")
            or request.cookies.get(SESSION_COOKIE)
            or request.headers.get("transfer-encoding")):
        return
    if (request.headers.get("content-length") or "0") != "0":
        return
    raise Problem(401, "Unauthenticated",
                  "no session token and no download ticket")


def _download_actor(request: Request, conn: psycopg.Connection,
                    sample_id: UUID, ticket: str | None) -> tuple[UUID, UUID | None]:
    """Who is downloading, and the ticket that proved it if one did.

    The two authentications cannot both be `Depends`: FastAPI resolves
    every dependency a route declares, so `Depends(_REQUIRE_DOWNLOAD)`
    would 401 a perfectly good ticket before this function ever ran. They
    are therefore composed by hand -- and they are composed out of the
    SAME callables the rest of the API uses (`session_token`,
    `current_user`, the hoisted `sample.download` gate, `require_step_up`),
    not reimplemented, because a second spelling of "is this session
    allowed" is how two halves of one control come to disagree.

    Ticket first, and only when one is actually presented: the session
    path is unchanged for every caller who sends a Bearer, which since
    2026-09-10 is every caller except the console. A request carrying
    BOTH spends the ticket, because this branch is the first one.

    The two branches check the same three things, by two routes. The
    session branch calls the gates above. The ticket branch gets the
    account half from `redeem_download_ticket`, which re-reads the
    holder's `is_active` and their `sample.download` through the same
    `holds_global_permission` `require_global` is built on -- in the
    SERVICE, so a second caller cannot skip it, exactly as the origin and
    label checks live there -- and the label half from `download()` below,
    which reads `user_ceiling` live. What the ticket branch does not and
    will not re-derive is the SESSION: that is the stated residual (0061,
    docs/17 F22), and it is a question about a credential this origin
    cannot resolve, not about the account.
    """
    if ticket:
        try:
            return _ticket_svc(conn).redeem_download_ticket(
                ticket, sample_id=sample_id, ip_hash=_ip_hash(request))
        except SampleError as exc:
            # 401 and not 403: a ticket is the credential on this path,
            # and a spent or expired one is an expired credential. One
            # answer for all four refusal reasons, because "already
            # redeemed" would tell the holder of a stolen ticket that it
            # was real and that somebody else got there first.
            raise Problem(401, "Unauthenticated", safe_detail(exc)) from exc
    raw = session_token(request, request.headers.get("authorization"))
    user = current_user(request, raw, conn)
    _REQUIRE_DOWNLOAD(user, conn)
    require_step_up(user, conn)
    return user.user_id, None


@router.post("/{sample_id}/download",
             dependencies=[Depends(_meter_download)])
@body_cap(_TICKET_BODY_CAP, what="a download ticket")
def download(
    sample_id: UUID,
    request: Request,
    #: The one-shot ticket, in the FORM BODY. Not a query parameter: a URL
    #: reaches the access log, the Referer and the browser history, and
    #: this one is a credential. Not JSON either, and that is not taste --
    #: `application/x-www-form-urlencoded` is a CORS-safelisted content
    #: type, so a ticket redemption is a SIMPLE cross-origin request that
    #: needs no preflight, while `application/json` would need
    #: `content-type` in `app._preflight`'s `Access-Control-Allow-Headers`
    #: and would fail with the console's "the request did not complete"
    #: until somebody added it.
    ticket: str | None = Form(default=None),
    _presented: None = Depends(_credential_presented),
    conn: psycopg.Connection = Depends(get_conn),
) -> Response:
    """The encrypted archive. The ONLY endpoint that touches sample bytes.

    The origin check is in the service, not here, so a second caller cannot
    skip it -- and the service reads CONFIGURATION for it, so there is
    nothing for this route to pass. It used to pass
    `request.url.scheme://request.url.netloc` under a comment calling that
    "the server's own view of the URL, never a header the client
    controls"; Starlette builds `request.url` from the Host header, so the
    comment was false and the check granted on a client-supplied value.
    The route no longer takes the request at all, which is the shape that
    cannot regress. These headers are the belt to those braces: even if
    something upstream decided to serve this as HTML, `sandbox` in the CSP
    means the browser will not execute it, and `nosniff` means it will not
    guess.

    ## Two ways to prove who you are

    A session (Bearer, or the cookie plus its CSRF header) is the original
    path and still works, for every caller that is not the console. A
    one-shot `ticket` in the form body is the other, minted on the
    application origin by `download-ticket`: the split means no `__Host-`
    cookie can reach this process, so the alternative to a ticket was the
    console carrying its session token to a second origin -- which it did
    until 2026-09-10 and does not do now. `_download_actor` composes both
    out of the same callables the rest of the API uses.

    Whichever proved it, the identity for the rest of this route is one
    user: the ticket's holder is the actor the labels are checked against,
    the audit names, and the custody row records.
    """
    actor_id, ticket_id = _download_actor(request, conn, sample_id, ticket)
    # The caller's ceiling, exactly as `detail()` twenty lines above already
    # does. Its absence here was the worst defect found in this codebase:
    # `detail()` 404'd an over-classified sample and this endpoint handed
    # the same caller its bytes one request later.
    #
    # Read LIVE, and on the ticket path that matters: the ticket was
    # minted against this ceiling up to a minute ago, and a clearance
    # withdrawn in between must bite before the bytes move.
    clearance, compartments = user_ceiling(conn, actor_id)
    try:
        blob, digest = _svc(conn).download(
            sample_id, actor_id=actor_id,
            clearance=clearance.name, compartments=compartments,
            ticket_id=ticket_id)
    except SampleError as exc:
        if "no such sample" in str(exc):
            # 404, not 409: "this sample exists but is not yours" is itself
            # a disclosure about a compartmented case.
            raise Problem(404, "Not found", "no such sample") from exc
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return Response(
        content=blob, media_type="application/octet-stream",
        headers={
            # Named for its hash. The attacker's filename never reappears.
            "Content-Disposition": f'attachment; filename="{digest}.zip"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "no-store",
            "X-Sample-Archive-Password": "infected",
        },
    )


class RejectBody(BaseModel):
    reason: str = Field(min_length=1)
    #: Defaults to destroying, because that is what a rejection means. The
    #: opt-out exists for the one case the service refuses outright: a
    #: sample under a legal hold, where preservation and destruction are
    #: both legal obligations and the caller has to say which one they are
    #: acting under. Making it a parameter rather than an override keeps
    #: the choice in the request body, where the audit row records it.
    purge_bytes: bool = True


@router.post("/{sample_id}/reject", response_model=SampleOut)
def reject(
    sample_id: UUID, body: RejectBody,
    user: CurrentUser = Depends(require_global("sample.analyse")),
    conn: psycopg.Connection = Depends(get_conn),
) -> SampleOut:
    """Record THAT something was rejected and why, without retaining the
    content. The bytes go; the row stays.

    Unless the sample is under a legal hold, in which case the service
    refuses and says so — docs/08: a hold overrides all deletion,
    everywhere.

    ## CR11 (2026-07-26) — the destructive path had no label check

    `reject(purge_bytes=True)` is irreversible: it deletes the object and
    zeroes the data key. It resolved the sample through `get()`, which is
    `WHERE id = %s` with no clearance, compartment or case predicate, and
    the route gated only on the GLOBAL `sample.analyse` role.

    `download()` composes the sample's labels with its case's before it
    will serve a byte. `reject()` — which destroys those same bytes
    forever — did not. So a MALWARE_ANALYST, who deliberately holds no
    case access at all, could permanently destroy a sample belonging to a
    compartmented case knowing only its UUID.

    The check runs BEFORE anything is deleted, and returns the same
    "no such sample" a nonexistent id gives: a 403 here would confirm that
    a particular sample exists in a case the caller cannot see.
    """
    clearance, comps = user_ceiling(conn, user.user_id)
    if _svc(conn).visible(sample_id, clearance=clearance.name,
                          compartments=comps) is None:
        raise Problem(404, "Not found", "no such sample")
    try:
        return _out(_svc(conn).reject(sample_id, actor_id=user.user_id,
                                      reason=body.reason,
                                      purge_bytes=body.purge_bytes))
    except SampleError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc


class AssignBody(BaseModel):
    analyst_id: UUID


@router.post("/{sample_id}/assign", response_model=SampleOut)
def assign(
    sample_id: UUID, body: AssignBody,
    user: CurrentUser = Depends(require_global("sample.analyse")),
    conn: psycopg.Connection = Depends(get_conn),
) -> SampleOut:
    try:
        return _out(_svc(conn).assign(sample_id, analyst_id=body.analyst_id,
                                      actor_id=user.user_id))
    except SampleError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc


class AnalysisBody(BaseModel):
    kind: str
    findings: dict = Field(default_factory=dict)
    extracted_selectors: list = Field(default_factory=list)
    yara_hits: list[str] = Field(default_factory=list)
    family_assessment: str | None = None
    confidence: str | None = None
    narrative: str | None = None
    tool: str | None = None
    tool_version: str | None = None


@router.post("/{sample_id}/analysis", response_model=dict, status_code=201)
def record_analysis(
    sample_id: UUID, body: AnalysisBody,
    user: CurrentUser = Depends(require_global("sample.analyse")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Findings are machine-readable by construction. A family attribution
    without a confidence is refused: it is an assessment, and one without a
    confidence is a fact wearing an assessment's clothes."""
    try:
        analysis_id = _svc(conn).record_analysis(
            sample_id, analyst_id=user.user_id, kind=body.kind,
            findings=body.findings, extracted_selectors=body.extracted_selectors,
            yara_hits=body.yara_hits or None,
            family_assessment=body.family_assessment, confidence=body.confidence,
            narrative=body.narrative, tool=body.tool,
            tool_version=body.tool_version)
    except SampleError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {"id": str(analysis_id)}


class DetonationBody(BaseModel):
    target: str
    exposure_level: str
    authorised_by: UUID | None = None
    note: str | None = None


@router.post("/{sample_id}/detonation", response_model=dict, status_code=201)
def request_detonation(
    sample_id: UUID, body: DetonationBody,
    user: CurrentUser = Depends(require_global("sample.detonate")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Record a detonation request. **Nothing is submitted anywhere** --
    docs/11 is emphatic that you integrate with a sandbox rather than build
    one, and no integration exists.

    Anything other than a private instance needs a named authoriser and a
    note, because submitting to a vendor or public sandbox exposes the
    sample AND your interest in it, and operators watch public sandboxes
    for their own samples.
    """
    try:
        det_id = _svc(conn).request_detonation(
            sample_id, requested_by=user.user_id, target=body.target,
            exposure_level=body.exposure_level,
            authorised_by=body.authorised_by, note=body.note)
    except SampleError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {"id": str(det_id),
            "submitted": False,
            "notice": "Recorded only. No sandbox integration exists; nothing "
                      "has been sent anywhere."}
