"""RunContext: what one poll of an authority adapter holds (the collection
foundation, docs/00 decision 69, 2026-09-24).

Everything a forum or Telegram poll does around its adapter lives here once,
so the adapters only parse: the route run_once resolved, the user
agent, ONE wall clock for the whole poll, the page and byte budgets, the
per-request pacing, the same-origin rule, the redirect rule, the 429 rule
and the custody log of every request sent.

## One call site

`_http_get` is the ONLY place a collection adapter's HTTP leaves this
process, and it is exactly docs/20 section 9's call:

    collection.fetch_response(url, route=self.route, max_redirects=0,
        accept_status=accept_status | REDIRECT_CODES,
        user_agent=self.user_agent, deadline=self.deadline, max_bytes=...)

`max_redirects=0` means the client never follows: a 3xx comes back as a
Fetched with its absolute `location` (query kept), and this module decides
(rule e below). The collector's wrapper is used rather than pinned_http
directly, so the suites that patch `collection._is_blocked` still reach
the connect.

## The rules of `fetch`, in order

(a) budget: BudgetSpent when the poll's wall clock is nearly spent, when
    the page budget is used, or when the byte budget is spent, and nothing
    is sent;
(b) same origin: the URL (absolute, or relative to the source's address)
    has the source's scheme, host and effective port and no user name, or
    nothing is sent;
(c) pace: the source's max_rps and, for a persona, its gap;
(d) one GET through `_http_get`. A route refusal is EgressUnavailable (a
    BLOCKED run); the poll's shared deadline running out mid request, or a
    page larger than the bytes the run has left, is BudgetSpent after the
    request is logged (2026-09-24: a slow board otherwise
    failed the whole walk and was read as parser ill health);
(e) a same-origin redirect is followed, paced and counted, at most three
    hops; any other comes back unfollowed, so an adapter can tell a login
    page by where it points;
(f) a 429, or a 503 carrying Retry-After, that the adapter did not accept
    is RateLimited;
(g) one request-log entry per request sent, the first 100 kept and the
    rest counted in a note.
"""
from __future__ import annotations

import hashlib
import re
import time
import urllib.parse
from datetime import datetime, timezone

from noctornal_api import collection, pinned_http
from noctornal_api.collection import (  # noqa: F401 - PersonaContext re-exported
    MAX_REQUEST_LOG,
    BudgetSpent,
    CollectionError,
    EgressUnavailable,
    PersonaContext,
    RateLimited,
    _attr,
)
from noctornal_api.egress_policy import normalise_host
from noctornal_api.pinned_http import (
    COLLECTOR_USER_AGENT,
    REDIRECT_CODES,
    DeadlineExceeded,
    DestinationRefused,
    HttpStatusError,
    OutboundError,
    ResponseTooLarge,
    RouteUnavailable,
    redact,
)
from noctornal_api.wording import agree, count_of

#: A same-origin redirect chain is followed at most this far.
MAX_SAME_ORIGIN_HOPS = 3
#: Nothing is started with less of the poll's wall clock left than this,
#: or a tenth of the whole allowance when that is smaller: a request that
#: will certainly be cut by the deadline only adds noise to the custody
#: log (2026-09-24).
REQUEST_FLOOR_S = 5.0
#: Each socket operation of one request.
REQUEST_TIMEOUT_S = 15.0
#: The request log's path and query caps (a hostile
#: same-origin Location controls the path).
MAX_LOGGED_PATH = 500
MAX_LOGGED_QUERY = 200

#: Form and session tokens: an input or attribute whose NAME matches has
#: its VALUE removed from stored markup, and a query parameter whose name
#: matches has its value removed from the request log. A backstop to the
#: adapter's own stripping.
_TOKEN_NAME = rb"(?:_xfToken|my_post_key|csrf|xsrf|authenticity_token|logout_hash|_token)"
_TOKEN_NAME_TEXT = re.compile(
    r"(?i)(?:_xfToken|my_post_key|csrf|xsrf|authenticity_token|logout_hash|_token)")
_TOKEN_IN = re.compile(rb"(?i)" + _TOKEN_NAME)

# LINEAR, and it has to be (2026-09-25). The first version
# put the token name between two bounded repetitions of the characters a
# name may carry, so on a hostile run such as b"csrf-" repeated every start
# position tried every split of the run: about 6 s of CPU per MiB, inside
# the persist transaction. Now a name is entered only where no name
# character precedes it (so a run is never re-scanned from inside), a
# lookahead confined to that run asks whether a token is in it, and the
# name is then taken whole and possessive ({1,128}+ never gives characters
# back). The substitutions are templates, so the regex engine does all of
# it. test_the_scrubber_is_linear_on_hostile_input times each shape.

#: The characters an attribute or input name may carry, and where one may
#: start: nowhere a name character precedes.
_NAME_CHAR = rb"[\w:.\-\[\]]"
_NAME_START = rb"(?<![\w:.\-\[\]])"
#: An attribute value: quoted either way, or bare. A quoted branch that
#: fails scans to the end once and the bare branch then consumes the quote,
#: so no stretch is scanned twice.
_ATTR_VALUE = rb"(\"[^\"]*\"|'[^']*'|[^\s>]+)"
#: data-csrf="...", csrf_token='...': an ATTRIBUTE whose own name carries a
#: token has its value emptied.
_TOKEN_ATTR = re.compile(
    rb"(?i)" + _NAME_START + rb"((?=" + _NAME_CHAR + rb"{0,128}?" + _TOKEN_NAME
    + rb")" + _NAME_CHAR + rb"{1,128}+\s*+=\s*+)" + _ATTR_VALUE)
#: ?_xfToken=abc in an href or a form action: the value removed.
_TOKEN_QUERY = re.compile(
    rb"(?i)([?&](?:amp;)?(?=[\w.\-]{0,128}?" + _TOKEN_NAME
    + rb")[\w.\-]{1,128}+=)[^&\"'\s<>#]*+")
#: Inside one input tag: its name attributes, and its value attribute.
_NAME_ATTR = re.compile(rb"(?i)" + _NAME_START + rb"name\s*+=\s*+" + _ATTR_VALUE)
_VALUE_ATTR = re.compile(
    rb"(?i)(" + _NAME_START + rb"value\s*+=\s*+)" + _ATTR_VALUE)
#: The longest input tag looked into.
_MAX_TAG = 4096
#: What `\b` reads as a word character in a bytes pattern, lower case.
_WORD_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789_")


def _unquoted(value: bytes) -> bytes:
    if len(value) >= 2 and value[:1] in (b'"', b"'") and value[-1:] == value[:1]:
        return value[1:-1]
    return value


def _scrub_input_tag(tag: bytes) -> bytes:
    """<input ... name="token-name" ... value="...">: the value emptied. A
    tag that names no token anywhere is returned after one search."""
    if not _TOKEN_IN.search(tag):
        return tag
    if any(_TOKEN_IN.search(_unquoted(m.group(1)))
           for m in _NAME_ATTR.finditer(tag)):
        return _VALUE_ATTR.sub(rb'\1""', tag)
    return tag


def _input_tags(data: bytes) -> bytes:
    """Every <input> tag passed through _scrub_input_tag, by a scan that
    visits each byte a bounded number of times: the next '>' is found once
    and reused until the scan passes it, so b"<input" repeated with no '>'
    costs one pass, not one pass per tag. A '<' inside an attribute value
    does not end a tag, as it does not in HTML."""
    lower = data.lower()
    out, pos, done, gt = [], 0, 0, -1
    while True:
        start = lower.find(b"<input", pos)
        if start < 0:
            break
        after = start + 6
        if after < len(lower) and lower[after] in _WORD_BYTES:
            pos = after  # <inputs>, <input_x>: not an input tag
            continue
        if gt < after:
            gt = lower.find(b">", after)
            if gt < 0:
                break
        if gt - start > _MAX_TAG:
            pos = after
            continue
        out.append(data[done:start])
        out.append(_scrub_input_tag(data[start:gt + 1]))
        done = pos = gt + 1
    out.append(data[done:])
    return b"".join(out)


def _scrub_raw(fragment: bytes) -> bytes:
    """An item's markup with the value of every form or session token
    removed, before it is stored. Linear in the fragment (at most 1 MiB),
    for the reason given above the patterns; a fragment that names no token
    anywhere is returned after one search."""
    data = bytes(fragment)
    if not _TOKEN_IN.search(data):
        return data
    data = _input_tags(data)
    data = _TOKEN_ATTR.sub(rb'\1""', data)
    data = _TOKEN_QUERY.sub(rb"\1", data)
    return data


def _logged_path(path: str) -> str:
    """A path for the custody log with the value of every token it carries
    removed, then redacted and capped (2026-09-25: a hostile
    same-origin Location controls the path, and some boards carry the form
    token in it). Two shapes: a path parameter (/logout;csrf=abc) and a
    segment named for a token followed by its value (/_xfToken/abc)."""
    segments = (path or "/").split("/")
    blank_next = False
    for i, segment in enumerate(segments):
        if blank_next:
            segments[i] = ""
            blank_next = False
            continue
        head, *params = segment.split(";")
        for j, part in enumerate(params):
            name, sep, _value = part.partition("=")
            if sep and _TOKEN_NAME_TEXT.search(name):
                params[j] = name + "="
        if params:
            segments[i] = ";".join([head, *params])
        # Exactly a token's name, so /help/csrf-explained/page2 keeps its
        # last segment: a custody log that blanks ordinary paths is a
        # worse record, not a safer one.
        if _TOKEN_NAME_TEXT.fullmatch(head):
            blank_next = True
    return redact("/".join(segments))[:MAX_LOGGED_PATH]


def _logged_query(query: str) -> str:
    """A query for the custody log: every token parameter's value removed,
    redacted, and capped."""
    if not query:
        return ""
    kept = []
    for part in query.split("&"):
        name, sep, _value = part.partition("=")
        if sep and _TOKEN_NAME_TEXT.search(name):
            kept.append(name + "=")
        else:
            kept.append(part)
    return redact("&".join(kept))[:MAX_LOGGED_QUERY]


def _origin(url: str) -> tuple[str, str, int] | None:
    """(scheme, normalised host, effective port) or None when the URL is
    not an http(s) address this collector could read. A URL carrying a
    user name is None: credentials never travel in a collection URL."""
    try:
        parts = urllib.parse.urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or not parts.hostname:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        port = parts.port or (443 if scheme == "https" else 80)
        return scheme, normalise_host(parts.hostname), port
    except Exception:  # noqa: BLE001 - anything unparseable is refused
        return None


class RunContext:
    """What one poll of an authority adapter holds.

    `route`: the EgressRoute run_once resolved (docs/20 section 9).
    `user_agent`: the collector's honest agent for a persona-less read, the
    persona's recorded browser identity for a persona that reads over the
    web. `deadline`: ONE pinned_http.Deadline(adapter.run_seconds), entered
    for the fetch and shared by every request of the poll (a Deadline
    serves sequential requests only, which is how `fetch` is called).
    """

    def __init__(self, *, source, run_id, adapter, route, persona=None,
                 fetcher=None, limiter=None, clock=time.monotonic):
        self.source = source
        self.run_id = run_id
        self.adapter = adapter
        self.route = route
        self.persona = persona
        self._fetcher = fetcher
        self._limiter = limiter
        self._clock = clock
        self.run_seconds = float(_attr(adapter, "run_seconds"))
        self.deadline = pinned_http.Deadline(self.run_seconds)
        self.deadline_at = clock() + self.run_seconds
        self.max_page_bytes = int(_attr(adapter, "max_page_bytes"))
        self.byte_budget = int(_attr(adapter, "max_run_bytes"))
        self.page_budget = self._page_budget(adapter, source)
        self.pages_used = 0
        self.bytes_used = 0
        self._log: list[dict] = []
        self._unlogged = 0
        self._budget_reason: str | None = None
        base = source.base_url or ""
        self._base = base
        self._origin = _origin(base) if base else None
        if persona is not None and _attr(adapter, "persona_http"):
            self.user_agent = persona.fingerprint.get("user_agent")
        else:
            self.user_agent = COLLECTOR_USER_AGENT

    @staticmethod
    def _page_budget(adapter, source) -> int:
        """The smaller of the adapter's pages, a page_budget the adapter's
        validate_config accepted, and floor(run_seconds x max_rps): a poll
        never asks for more pages than its pace allows in its time."""
        pages = int(_attr(adapter, "max_pages") or 1)
        config = getattr(source, "parser_config", None) or {}
        wanted = config.get("page_budget")
        if isinstance(wanted, int) and not isinstance(wanted, bool) and wanted > 0 \
                and not _attr(adapter, "validate_config")({"page_budget": wanted}):
            pages = min(pages, wanted)
        paced = int(float(_attr(adapter, "run_seconds")) * float(source.max_rps or 0))
        return max(1, min(pages, paced))

    # -- the shared deadline -------------------------------------------------

    def __enter__(self) -> RunContext:
        self.deadline.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        self.deadline.__exit__(*exc)

    def remaining(self) -> float:
        return max(0.0, self.deadline_at - self._clock())

    def pace(self) -> None:
        """The source's max_rps and, as a persona, the persona's gap."""
        if self._limiter is None:
            return
        self._limiter.wait(self.source.id, float(self.source.max_rps or 1))
        if self.persona is not None:
            self._limiter.wait_persona(
                self.persona.persona_id,
                float(_attr(self.adapter, "persona_min_gap_s") or 0))

    # -- the log -----------------------------------------------------------

    def record_request(self, *, target: str, status: int | None, nbytes: int,
                       sha256_hex: str | None) -> None:
        """A request an adapter made that did not go through `fetch` (a
        Telegram RPC, named as its target)."""
        self._append({"at": _now_iso(),
                      "path": redact(str(target))[:MAX_LOGGED_PATH],
                      "query": "", "status": status, "bytes": int(nbytes),
                      "sha256": sha256_hex})

    def _append(self, entry: dict) -> None:
        if len(self._log) < MAX_REQUEST_LOG:
            self._log.append(entry)
        else:
            self._unlogged += 1

    def _log_url(self, url: str, status: int | None, body: bytes | None) -> None:
        parts = urllib.parse.urlsplit(url)
        self._append({
            "at": _now_iso(),
            "path": _logged_path(parts.path or "/"),
            "query": _logged_query(parts.query),
            "status": status,
            "bytes": len(body) if body is not None else 0,
            "sha256": hashlib.sha256(body).hexdigest() if body is not None else None})

    def logged(self) -> list[dict]:
        return list(self._log)

    def notes(self) -> list[str]:
        """The run's BUDGET_SPENT notes: why the walk stopped, and how many
        requests are counted rather than listed."""
        out = []
        if self._budget_reason:
            out.append(f"This poll stopped at its budget: {self._budget_reason}.")
        if self._unlogged:
            out.append(
                f"{count_of(self._unlogged, 'further request', 'further requests')} "
                f"{agree(self._unlogged, 'was', 'were')} made and "
                f"{agree(self._unlogged, 'is', 'are')} counted, not listed.")
        return out

    def _spent(self, reason: str) -> BudgetSpent:
        self._budget_reason = reason
        return BudgetSpent(f"This poll stopped at its budget: {reason}.")

    # -- one request ---------------------------------------------------------

    def fetch(self, url: str, *, accept_status=frozenset(),
              max_bytes: int | None = None):
        """One GET on the source's own origin (the rules in the module
        docstring). Returns the pinned client's Fetched."""
        accept = frozenset(accept_status)
        target = urllib.parse.urljoin(self._base, url) if self._base else url
        hops = 0
        while True:
            self._check_budget()
            origin = _origin(target)
            if origin is None or self._origin is None or origin != self._origin:
                raise CollectionError(
                    "refused a request to another site: collection stays on "
                    "the source's own origin")
            self.pace()
            fetched = self._http_get(target, accept, max_bytes)
            if (fetched.status in REDIRECT_CODES and fetched.location
                    and fetched.status not in accept
                    and hops < MAX_SAME_ORIGIN_HOPS
                    and _origin(fetched.location) == self._origin):
                hops += 1
                target = fetched.location
                continue
            return fetched

    def _check_budget(self) -> None:
        floor = min(REQUEST_FLOOR_S, 0.1 * self.run_seconds)
        if self.remaining() <= floor or self.deadline.spent():
            raise self._spent("its wall clock ran out")
        if self.pages_used >= self.page_budget:
            raise self._spent(
                f"it read the {count_of(self.page_budget, 'page', 'pages')} "
                f"its budget allows")
        if self.bytes_used >= self.byte_budget:
            raise self._spent("it read the bytes its budget allows")

    def _http_get(self, url: str, accept: frozenset[int], max_bytes: int | None):
        """THE one outbound call of a collection adapter (docs/20 section 9)."""
        page_cap = min(int(max_bytes or self.max_page_bytes), self.max_page_bytes)
        left = self.byte_budget - self.bytes_used
        cap = max(0, min(page_cap, left))
        fetcher = self._fetcher or collection.fetch_response
        self.pages_used += 1
        try:
            fetched = fetcher(
                url, route=self.route, max_redirects=0,
                accept_status=accept | REDIRECT_CODES,
                user_agent=self.user_agent, deadline=self.deadline,
                max_bytes=cap,
                timeout=max(0.5, min(REQUEST_TIMEOUT_S, self.remaining())))
        except (RouteUnavailable, DestinationRefused) as exc:
            if exc.request_sent:
                self._log_url(url, None, None)
            raise EgressUnavailable(redact(str(exc))) from None
        except DeadlineExceeded as exc:
            if exc.request_sent:
                self._log_url(url, None, None)
            raise self._spent("its wall clock ran out") from None
        except ResponseTooLarge as exc:
            self._log_url(url, None, None)
            if cap < page_cap:
                # The page was cut by what the RUN had left, not by the page
                # cap: the budget is spent, and what was read is kept.
                raise self._spent("it read the bytes its budget allows") from None
            raise CollectionError(
                f"a page was larger than the "
                f"{count_of(page_cap, 'byte', 'bytes')} this parser reads, "
                f"and was abandoned") from exc
        except HttpStatusError as exc:
            self._log_url(url, exc.status, None)
            if exc.status == 429 or (exc.status == 503
                                     and exc.retry_after is not None):
                raise RateLimited(exc.retry_after if exc.retry_after is not None
                                  else 60.0) from None
            raise
        except OutboundError as exc:
            if exc.request_sent:
                self._log_url(url, None, None)
            raise
        body = fetched.body or b""
        self.bytes_used += len(body)
        self._log_url(fetched.url or url, fetched.status, body)
        return fetched


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
