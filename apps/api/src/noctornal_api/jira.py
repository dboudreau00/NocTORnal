"""Jira as a notification channel (F7, 2026-09-24).

JIRA stays what migration 0029 made it: a per-recipient channel on the
existing ledger, one notify.delivery row per notification per channel. A
recipient opts in on their own preference (audited); an administrator
decides WHERE (one destination), WHAT (a ceiling, a field exposure and the
routed kinds) and HOW it leaves (the integration route "jira", created
in Administration, Egress); a case owner can keep a case out entirely.

The drain maps each due JIRA delivery to create-or-comment on ONE Jira
issue per work item (`notify.jira_link`), and records per event whether
that event is already on the issue (`notify.jira_event`), so N recipients
of one event make one post and two identical events make two. Nothing
comes back from Jira and nothing is written to the graph.

## Reach (docs/00 decisions 68 and 72)

This module never opens a socket. Every call is
`pinned_http.fetch_response(..., route=egress.route_for("integration",
"jira", ...))`: which host may be reached is the route's allowlist, written
by an administrator with step-up and audited; a private Data Center
address is reachable only when an allowlist entry names it; egress_policy
is the one classifier; nothing follows a redirect, so the credential never
reaches a target it was not meant for.

## Idempotency without an uncertain-write flag

A create or a comment whose outcome is unknown is never repeated blind.
Every create carries a random ref label (`noctornal-ref-<16 chars>`) and
every post ends "NocTORnal ref <marker>"; a retry after an attempt first
waits SETTLE for Jira's search index and then looks for its own label or
marker. A duplicate issue is possible only when the index lags by more than
SETTLE, and it is visible: two issues carrying one ref label.

## Never

No body, entity names, selectors, compartments, recipient or actor
identity, internal ids, assignee, reporter mapping or custom field ever
reaches Jira. At STUB exposure not even the case code or the grouping of
work by case does. A notification about no case is never routed.
"""
from __future__ import annotations

import base64
import email.utils
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import NAMESPACE_URL, UUID, uuid5

import psycopg
from psycopg.types.json import Json

from noctornal_api import pinned_http
from noctornal_api.egress import Destination, RouteUnavailable, can_egress
from noctornal_api.lookup_adapters import json_depth
from noctornal_api.egress_policy import Refusal, Rule, split_url
from noctornal_api.notifications import KINDS
from noctornal_api.security import envelope
from noctornal_api.security.access import AccessResolutionError, tlp_from_name
from noctornal_api.wording import agree, count_of

log = logging.getLogger("noctornal.jira")

FLAVOURS = ("AUTO", "CLOUD", "DATA_CENTER")
AUTH_KINDS = ("CLOUD_API_TOKEN", "DC_PAT", "DC_BASIC")
EXPOSURES = ("STUB", "SUBJECT", "SUMMARY")
_EXPOSURE_RANK = {"STUB": 0, "SUBJECT": 1, "SUMMARY": 2}
CEILINGS = ("CLEAR", "GREEN", "AMBER")
ROUTE = "jira"

#: The routing ALLOWLIST: one fixed sentence per routable kind. A kind
#: nobody decided about is never routable (fail closed), so a feature
#: registering a new kind can never make it reach a ticket system.
JIRA_TASKS: dict[str, str] = {
    "APPROVAL_REQUESTED": "A second signature is needed in NocTORnal. Sign in to "
                          "review the request.",
    "APPROVAL_DECIDED": "The second-signature request was decided.",
    "PROPOSAL_QUEUED": "Proposals are waiting in the triage queue. Sign in to "
                       "review them.",
    "CASE_REVIEW_DUE": "A case review is due. Sign in to record it.",
    "MERGE_PERFORMED": "Two entities were merged. Sign in to review the merge.",
    "MERGE_REVERSED": "A merge was reversed.",
    "EVIDENCE_INTEGRITY_ALARM": "An exhibit failed its integrity check. Sign in "
                                "to investigate.",
    "FEED_SELECTOR_HIT": "A feed record matched a watched selector. Sign in to "
                         "triage it.",
}
#: docs/07's work items.
DEFAULT_KINDS = ("APPROVAL_REQUESTED", "APPROVAL_DECIDED", "PROPOSAL_QUEUED",
                 "CASE_REVIEW_DUE")
#: Kinds deliberately never routed, named so the Jira card can say so. It
#: may name kinds not registered yet; routability is JIRA_TASKS alone.
#: ESCALATION is here because escalation_to_owner's summary names the
#: original kind, which for BREAK_GLASS_INVOKED is the emergency-access
#: pattern itself.
JIRA_NEVER_KINDS = frozenset({
    "BREAK_GLASS_INVOKED", "ESCALATION", "COLLECTION_AUTHORITY_PENDING",
    "PERSONA_SUSPENDED", "PERSONA_SESSION_DUPLICATED", "SAMPLE_SCREENING_MATCH",
    "DETONATION_REQUESTED", "DETONATION_SIGNOFF_REQUESTED",
    "DETONATION_SIGNOFF_DECIDED", "SANDBOX_RESULT", "SAMPLE_WITHDRAWN",
    # The outbound credential vault's own (F15).
    "PROVIDER_CHANGE_REQUESTED", "LOOKUP_SIGNOFF_REQUESTED",
    "LOOKUP_SIGNOFF_DECIDED",
})

JIRA_MAX_PER_DRAIN = 50
#: Wall clock for all Jira work in one pass: email is never behind Jira,
#: and neither is the collection poll the cron loop runs next.
JIRA_PASS_SECONDS = 60.0
REQUEST_SECONDS = 20.0
TEST_SECONDS = 30.0
MAX_RESPONSE_BYTES = 1024 * 1024
#: Jira's answers nest a handful of levels (createmeta is the deepest, about
#: eight). json.loads recurses once per level, so a megabyte of brackets
#: raised RecursionError, which is not a ValueError: it escaped the pass and
#: the drain, silencing the review and escalation producers on every cron
#: pass (2026-09-25). Anything deeper is not an answer.
MAX_JSON_DEPTH = 32
RETRY_AFTER_FLOOR_S = 60
RETRY_AFTER_CAP_S = 3600
#: Jira's search index lag allowance: nothing is searched for, or posted
#: again, until an attempt is this old.
SETTLE = timedelta(minutes=2)
TEST_FRESH_FOR = timedelta(hours=24)
USER_AGENT = "NocTORnal-jira/1"
#: Statuses Jira answers that this module classifies itself.
JIRA_ANSWERS = frozenset({301, 302, 303, 307, 308, 400, 401, 403, 404, 409, 429})
OVERDUE_AFTER = timedelta(minutes=30)
#: How many links with an unsettled create one pass reconciles.
RECONCILE_PER_PASS = 10

CEILING_ENV = "NOCTORNAL_JIRA_CEILING"
CA_FILE_ENV = "NOCTORNAL_JIRA_CA_FILE"
ALLOW_HTTP_ENV = "NOCTORNAL_JIRA_ALLOW_HTTP"
#: The network a Data Center Jira answers from, when it is on one: the
#: declared rule carries it (docs/20 section 9, the Jira row), so a
#: private instance is reachable by name and nothing else in that range is
#: (2026-09-25).
NETWORK_ENV = "NOCTORNAL_JIRA_NETWORK"


def jira_network(env=None) -> tuple[object | None, str | None]:
    """(network or None, None) or (None, a sentence). The sentence never
    quotes the value."""
    raw = (os.environ if env is None else env).get(NETWORK_ENV, "").strip()
    if not raw:
        return None, None
    try:
        return ipaddress.ip_network(raw.strip("[]"), strict=True), None
    except ValueError:
        return None, (f"{NETWORK_ENV} is not a network written with its prefix (for "
                      f"example 10.40.0.0/24), so the Jira route cannot say where Jira "
                      f"answers from.")


def _loads(body: bytes):
    """Jira's answer as JSON, or ValueError. Never RecursionError."""
    if json_depth(body) > MAX_JSON_DEPTH:
        raise ValueError(f"the answer nests deeper than {MAX_JSON_DEPTH} levels")
    try:
        return json.loads(body.decode("utf-8"))
    except RecursionError:
        raise ValueError("the answer nests too deeply") from None


EXPOSURE_WORDS = {
    "STUB": "Only that work is waiting. No case code.",
    "SUBJECT": "Case code, what happened, priority and TLP marking.",
    "SUMMARY": "As above, plus the one-line summary that email carries.",
}

# Values taken from Jira are shape-checked before any use.
_ISSUE_KEY = re.compile(r"^[A-Z][A-Z0-9_]{1,19}-[1-9][0-9]{0,9}$")
_NUMERIC_ID = re.compile(r"^[0-9]{1,18}$")
_STATUS_CATEGORIES = frozenset({"new", "indeterminate", "done", "undefined"})
_VERSION = re.compile(r"^[0-9][0-9A-Za-z._-]{0,31}$")
_DEPLOYMENT_TYPES = {"Cloud": "CLOUD", "Server": "DATA_CENTER",
                     "DataCenter": "DATA_CENTER"}
_ERROR_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_PROJECT_KEY = re.compile(r"^[A-Z][A-Z0-9_]{1,19}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_REF_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"


class JiraError(Exception):
    """A configuration route refused: the sentence is the operator's."""

    def __init__(self, message: str, *, status: int = 400):
        super().__init__(message)
        self.status = status


def routable(kind: str) -> bool:
    return kind in JIRA_TASKS


def production() -> bool:
    from noctornal_api.transports import production as _production
    return _production()


def _http_allowed() -> bool:
    return (not production() and os.environ.get(ALLOW_HTTP_ENV, "").strip().lower()
            in {"1", "true", "yes", "on"})


def ca_context() -> ssl.SSLContext | None:
    """A private CA for a Data Center instance, or None for the system
    store. fetch_response refuses a context that does not verify."""
    path = os.environ.get(CA_FILE_ENV, "").strip()
    if not path:
        return None
    return ssl.create_default_context(cafile=path)


# ---------------------------------------------------------------------------
# The destination
# ---------------------------------------------------------------------------

_DEST_COLUMNS = (
    "id, label, base_url, host, port, flavour, auth_kind, auth_user, "
    "credential_ciphertext, credential_key_id, credential_set_at, "
    "credential_set_by, project_key, issue_type, issue_type_id, ceiling, "
    "field_exposure, kinds, state, health, health_detail, health_changed_at, "
    "tested_at, server_version, deployment_type, edit_caveat, created_at, "
    "created_by, updated_at, updated_by, activated_at, retired_at")


@dataclass(frozen=True)
class Dest:
    id: UUID
    label: str
    base_url: str
    host: str
    port: int
    flavour: str
    auth_kind: str
    auth_user: str | None
    credential_ciphertext: bytes
    credential_key_id: str | None
    credential_set_at: datetime
    credential_set_by: UUID
    project_key: str
    issue_type: str
    issue_type_id: str | None
    ceiling: str
    field_exposure: str
    kinds: tuple[str, ...]
    state: str
    health: str
    health_detail: str | None
    health_changed_at: datetime | None
    tested_at: datetime | None
    server_version: str | None
    deployment_type: str | None
    edit_caveat: str | None
    created_at: datetime
    created_by: UUID
    updated_at: datetime
    updated_by: UUID
    activated_at: datetime | None
    retired_at: datetime | None

    @property
    def api_version(self) -> int:
        return 3 if self.flavour == "CLOUD" else 2

    @property
    def routed_kinds(self) -> tuple[str, ...]:
        """The destination's kinds that are routable at all."""
        return tuple(k for k in self.kinds if routable(k))


def _dest(row) -> Dest:
    values = list(row)
    values[8] = bytes(values[8] or b"")
    values[17] = tuple(values[17] or ())
    return Dest(*values)


def live_destination(conn: psycopg.Connection) -> Dest | None:
    """The one destination that is not RETIRED, or None."""
    row = conn.execute(
        f"SELECT {_DEST_COLUMNS} FROM notify.jira_destination "
        f"WHERE state <> 'RETIRED'").fetchone()
    return _dest(row) if row else None


@dataclass(frozen=True)
class Routing:
    destination_id: UUID
    state: str
    kinds: frozenset[str]


def routing(conn: psycopg.Connection) -> Routing | None:
    """What queue time and preferences route to: the live destination once
    it has been activated (ACTIVE, PAUSED, or back in DRAFT after a change
    of where it points, which holds rows rather than dropping them).
    A never-activated draft routes nothing."""
    row = conn.execute(
        """SELECT id, state, kinds FROM notify.jira_destination
            WHERE state <> 'RETIRED' AND activated_at IS NOT NULL""").fetchone()
    if row is None:
        return None
    return Routing(row[0], row[1], frozenset(k for k in (row[2] or ()) if routable(k)))


def case_blocked(conn: psycopg.Connection, case_id: UUID) -> bool:
    return conn.execute(
        "SELECT 1 FROM notify.case_route_block WHERE case_id = %s AND channel = 'JIRA'",
        (case_id,)).fetchone() is not None


def effective_ceiling(dest: Dest) -> str:
    """The stricter of the row's ceiling and NOCTORNAL_JIRA_CEILING. An
    unparseable host cap is passed through, so can_egress fails closed with
    unknown_classification rather than this guessing."""
    env = os.environ.get(CEILING_ENV, "").strip()
    if not env:
        return dest.ceiling
    try:
        cap = tlp_from_name(env.upper())
    except AccessResolutionError:
        return env
    return min(tlp_from_name(dest.ceiling), cap).name


def browse_url(base: str, key: str, comment_id: str | None = None) -> str:
    url = f"{base}/browse/{key}"
    if comment_id:
        url += f"?focusedCommentId={comment_id}"
    return url


# ---------------------------------------------------------------------------
# Rendering (pure)
# ---------------------------------------------------------------------------

def work_key(out, exposure: str) -> UUID:
    """One issue per work item. At SUBJECT and SUMMARY an approval request
    and its decision share an issue, a merge and its reversal share one,
    PROPOSAL_QUEUED keeps one standing issue per case; at STUB every event
    is its own issue, so the Jira audience cannot count cases or follow a
    case's rhythm through standing issues."""
    event = out.event_id or out.notification_id
    if exposure != "STUB" and out.object_id is not None:
        return uuid5(NAMESPACE_URL, f"noctornal:jira-work:{out.case_id}:"
                                    f"{out.object_type}:{out.object_id}")
    return uuid5(NAMESPACE_URL, f"noctornal:jira-work:event:{event}")


def marker(ref: str, event_id: UUID) -> str:
    """Deterministic per event and issue, and reveals no internal id."""
    return hashlib.sha256(f"{ref}:{event_id}".encode("ascii")).hexdigest()[:12]


def new_ref() -> str:
    return "".join(secrets.choice(_REF_ALPHABET) for _ in range(16))


_WIKI_SPECIAL = set("\\*_?-+^~|!{}[]#")


def wiki_escape(text: str) -> str:
    """Data Center wiki markup: every interpolated string escaped, newlines
    and control characters removed."""
    flat = _CONTROL.sub(" ", text or "")
    return "".join("\\" + ch if ch in _WIKI_SPECIAL else ch for ch in flat)


def _clean(text: str, cap: int) -> str:
    return _CONTROL.sub(" ", text or "").strip()[:cap]


def _label(text: str) -> str:
    return re.sub(r"[^a-z0-9_-]+", "-", text.lower()).strip("-")[:255]


@dataclass(frozen=True)
class Rendered:
    summary: str
    description: object
    comment: object
    labels: tuple[str, ...]


def _doc(lines: list[tuple[str, str | None]], api_version: int):
    """Cloud: ADF text nodes only (a link is a text node with a link mark);
    Data Center: one wiki string, each line already escaped."""
    if api_version == 3:
        content = []
        for text, href in lines:
            node = {"type": "text", "text": text}
            if href:
                node["marks"] = [{"type": "link", "attrs": {"href": href}}]
            content.append({"type": "paragraph", "content": [node]})
        return {"type": "doc", "version": 1, "content": content}
    return "\n".join(text for text, _ in lines)


def render(out, *, exposure: str, api_version: int, ref: str, mark: str,
           base: str) -> Rendered:
    """What one event puts on Jira at `exposure`. Reads the subject and
    the summary only; `Outgoing` carries no body (decision 46)."""
    ui = f"{base}/ui/"
    dc = api_version != 3
    esc = wiki_escape if dc else (lambda s: _clean(s, 4000))
    ref_line = (f"NocTORnal ref {mark}", None)
    labels = ["noctornal", f"noctornal-ref-{ref}"]
    if exposure == "STUB":
        summary = "[NocTORnal] Work is waiting"
        description = [("There is work waiting for your team in NocTORnal. Nothing "
                        "about it is sent here.", None),
                       ("Sign in to see it: " + ui, ui if not dc else None),
                       ref_line]
        comment = [("More work is waiting in NocTORnal. Sign in to see it: " + ui,
                    ui if not dc else None), ref_line]
        return Rendered(summary, _doc(description, api_version),
                        _doc(comment, api_version), tuple(labels))
    task = JIRA_TASKS.get(out.kind, "Work is waiting in NocTORnal.")
    raised = out.raised_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M") \
        if out.raised_at else "at an unrecorded time"
    tlp = f"TLP:{esc(out.classification)}. Handle accordingly."
    summary = _clean(f"[NocTORnal] {out.subject}", 255)
    lines = [(task, None)]
    if exposure == "SUMMARY":
        lines.append((esc(out.summary), None))
    lines += [(f"Raised {raised} UTC, priority {out.priority}.", None),
              (tlp, None),
              ("Sign in to read the detail: " + ui, ui if not dc else None),
              ("The content stays in NocTORnal.", None),
              ref_line]
    comment = [("Update: " + esc(out.subject), None)]
    if exposure == "SUMMARY":
        comment.append((esc(out.summary), None))
    comment += [(tlp, None), ref_line]
    labels += [f"noctornal-{_label(out.kind)}", f"noctornal-p{out.priority}",
               f"tlp-{_label(out.classification)}"]
    return Rendered(summary, _doc(lines, api_version), _doc(comment, api_version),
                    tuple(labels))


# ---------------------------------------------------------------------------
# The client (network only through pinned_http)
# ---------------------------------------------------------------------------

class JiraHttpError(Exception):
    """One classified failure. `kind` is RATE_LIMITED, AUTH, NOT_FOUND,
    INVALID, REDIRECT, SERVER, UNREACHABLE or TIMEOUT. `detail` never holds
    Jira's error text or a value it echoed: validators echo rejected
    values, and those are case text."""

    def __init__(self, kind: str, detail: str, *, status: int | None = None,
                 retry_after: float | None = None):
        super().__init__(detail)
        self.kind = kind
        self.status = status
        self.retry_after = retry_after
        self.detail = detail


#: Faults an operator fixes (later passes hold) versus outages (retried
#: behind a one-attempt circuit).
CONFIG_FAULTS = frozenset({"AUTH", "REDIRECT", "INVALID"})


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        seconds = float(value)
    else:
        try:
            when = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        seconds = (when - datetime.now(timezone.utc)).total_seconds()
    return min(max(seconds, 0.0), 86400.0)


def _auth_header(dest: Dest, credential: str) -> str:
    if dest.auth_kind == "DC_PAT":
        return "Bearer " + credential
    user = dest.auth_user or ""
    return "Basic " + base64.b64encode(f"{user}:{credential}".encode()).decode("ascii")


def _q(value: str) -> str:
    return urllib.parse.quote(value, safe="")


class JiraClient:
    """About eight REST calls, each named once. `fetch` is injectable so
    the client is tested without a network; the real one is the pinned
    client."""

    def __init__(self, dest: Dest, credential: str, *, route,
                 fetch: Callable = pinned_http.fetch_response,
                 budget_end: float | None = None, clock: Callable = time.monotonic,
                 api_version: int | None = None):
        self.dest = dest
        self._credential = credential
        self.route = route
        self._fetch = fetch
        self._budget_end = budget_end
        self._clock = clock
        self.v = api_version or dest.api_version

    def _deadline(self) -> float:
        left = REQUEST_SECONDS
        if self._budget_end is not None:
            left = min(left, self._budget_end - self._clock())
        if left <= 0.5:
            raise JiraHttpError("TIMEOUT", "the pass ran out of time before this call")
        return left

    def _call(self, method: str, path: str, body=None, *, messages: bool = False):
        url = self.dest.base_url + path
        headers = {"Accept": "application/json",
                   "Authorization": _auth_header(self.dest, self._credential)}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        try:
            fetched = self._fetch(
                url, route=self.route, method=method, headers=headers, body=data,
                accept_status=JIRA_ANSWERS, max_redirects=0, user_agent=USER_AGENT,
                deadline=self._deadline(), max_bytes=MAX_RESPONSE_BYTES,
                tls_context=ca_context(), secrets=(self._credential,))
        except pinned_http.HttpStatusError as exc:
            if exc.status == 503 and exc.retry_after is not None:
                raise JiraHttpError("RATE_LIMITED", f"Jira answered {exc.status}",
                                    status=exc.status,
                                    retry_after=exc.retry_after) from None
            raise JiraHttpError("SERVER", f"Jira answered {exc.status}",
                                status=exc.status, retry_after=exc.retry_after) from None
        except pinned_http.DeadlineExceeded:
            raise JiraHttpError("TIMEOUT", "Jira did not answer in time") from None
        except pinned_http.CollectionError as exc:
            raise JiraHttpError(
                "UNREACHABLE", "Jira unreachable: "
                + pinned_http.redact(str(exc), secrets=(self._credential,))) from None
        status = fetched.status
        if 300 <= status < 400:
            host = None
            if fetched.location:
                try:
                    host = urllib.parse.urlsplit(fetched.location).hostname
                except ValueError:
                    host = None
            raise JiraHttpError(
                "REDIRECT", f"Jira answered with a redirect to {host or 'another address'}. "
                "The base URL is probably missing its context path or its https.",
                status=status)
        if status == 429:
            raise JiraHttpError("RATE_LIMITED", "Jira asked to slow down (HTTP 429)",
                                status=status,
                                retry_after=_retry_after(fetched.headers.get("Retry-After")))
        if status in (401, 403):
            raise JiraHttpError("AUTH", f"Jira refused the credential (HTTP {status})",
                                status=status)
        if status == 404:
            raise JiraHttpError("NOT_FOUND", "Jira answered 404", status=status)
        if status in (400, 409):
            raise JiraHttpError("INVALID", self._invalid(status, fetched.body, messages),
                                status=status)
        if not fetched.body:
            return {}
        try:
            return _loads(fetched.body)
        except (UnicodeDecodeError, ValueError):
            raise JiraHttpError("INVALID", f"Jira answered {status} with a body that "
                                "is not JSON", status=status) from None

    @staticmethod
    def _invalid(status: int, body: bytes, messages: bool) -> str:
        """The status and the NAMES of the keys of Jira's `errors` object,
        never errorMessages and never a value (validators echo values, and
        those are case text). Only the Test route, which sends no case
        text, may show Jira's own messages."""
        names: list[str] = []
        texts: list[str] = []
        try:
            parsed = _loads(body) if body else {}
        except (UnicodeDecodeError, ValueError):
            parsed = {}
        if isinstance(parsed, dict):
            errors = parsed.get("errors")
            if isinstance(errors, dict):
                names = sorted(k for k in errors if isinstance(k, str) and _ERROR_KEY.match(k))
            if messages and isinstance(parsed.get("errorMessages"), list):
                texts = [_clean(str(m), 200) for m in parsed["errorMessages"][:3]]
        detail = f"Jira refused the request (HTTP {status})"
        if names:
            detail += ": fields " + ", ".join(names[:10])
        if texts:
            detail += ". " + " ".join(texts)
        return detail[:500]

    # -- calls ---------------------------------------------------------------

    def server_info(self) -> tuple[str, str | None]:
        info = self._call("GET", "/rest/api/2/serverInfo", messages=True)
        deployment = info.get("deploymentType") if isinstance(info, dict) else None
        version = info.get("version") if isinstance(info, dict) else None
        if deployment not in _DEPLOYMENT_TYPES:
            raise JiraHttpError("INVALID", "Jira's serverInfo names no deployment type "
                                "this build knows")
        if version is not None and (not isinstance(version, str) or not _VERSION.match(version)):
            version = None
        return deployment, version

    def myself(self) -> str:
        me = self._call("GET", f"/rest/api/{self.v}/myself", messages=True)
        name = me.get("displayName") if isinstance(me, dict) else None
        return _clean(str(name), 80) if name else "the service account"

    def project(self, key: str) -> None:
        self._call("GET", f"/rest/api/{self.v}/project/{_q(key)}", messages=True)

    def issue_types(self, key: str) -> list[tuple[str, str]]:
        got = self._call("GET", f"/rest/api/{self.v}/issue/createmeta/{_q(key)}/issuetypes",
                         messages=True)
        items = (got.get("issueTypes") or got.get("values") or []) if isinstance(got, dict) else []
        out = []
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("id"), str) \
                    and _NUMERIC_ID.match(item["id"]):
                out.append((item["id"], _clean(str(item.get("name", "")), 80)))
        return out

    def issue_type_fields(self, key: str, type_id: str) -> set[str]:
        got = self._call("GET", f"/rest/api/{self.v}/issue/createmeta/{_q(key)}/"
                                f"issuetypes/{_q(type_id)}", messages=True)
        items = (got.get("fields") or got.get("values") or []) if isinstance(got, dict) else []
        if isinstance(items, dict):
            return {k for k in items if isinstance(k, str)}
        return {i.get("fieldId") for i in items
                if isinstance(i, dict) and isinstance(i.get("fieldId"), str)}

    def create_issue(self, fields: dict) -> tuple[str, str]:
        got = self._call("POST", f"/rest/api/{self.v}/issue", {"fields": fields})
        issue_id = got.get("id") if isinstance(got, dict) else None
        key = got.get("key") if isinstance(got, dict) else None
        if not (isinstance(issue_id, str) and _NUMERIC_ID.match(issue_id)
                and isinstance(key, str) and _ISSUE_KEY.match(key)):
            raise JiraHttpError("INVALID", "Jira's answer to a create names no valid issue")
        return issue_id, key

    def add_comment(self, key: str, body) -> str:
        got = self._call("POST", f"/rest/api/{self.v}/issue/{_q(key)}/comment", {"body": body})
        comment_id = got.get("id") if isinstance(got, dict) else None
        if not (isinstance(comment_id, str) and _NUMERIC_ID.match(comment_id)):
            raise JiraHttpError("INVALID", "Jira's answer to a comment names no valid id")
        return comment_id

    def issue_status(self, key: str) -> str:
        got = self._call("GET", f"/rest/api/{self.v}/issue/{_q(key)}?fields=status")
        try:
            category = got["fields"]["status"]["statusCategory"]["key"]
        except (KeyError, TypeError):
            category = None
        if category not in _STATUS_CATEGORIES:
            raise JiraHttpError("INVALID", "Jira's issue status is not one this build knows")
        return category

    def add_label(self, key: str, label: str) -> None:
        self._call("PUT", f"/rest/api/{self.v}/issue/{_q(key)}",
                   {"update": {"labels": [{"add": label}]}})

    def edit_labels_allowed(self, key: str) -> bool:
        got = self._call("GET", f"/rest/api/{self.v}/issue/{_q(key)}/editmeta")
        fields = got.get("fields") if isinstance(got, dict) else None
        return isinstance(fields, dict) and "labels" in fields

    def search_ref(self, project_key: str, ref: str) -> tuple[str, str] | None:
        jql = f'project = "{project_key}" AND labels = "noctornal-ref-{ref}"'
        path = "/rest/api/3/search/jql" if self.v == 3 else "/rest/api/2/search"
        got = self._call("POST", path, {"jql": jql, "fields": ["summary"], "maxResults": 2})
        issues = got.get("issues") if isinstance(got, dict) else None
        if not isinstance(issues, list) or not issues:
            return None
        first = issues[0] if isinstance(issues[0], dict) else {}
        issue_id, key = first.get("id"), first.get("key")
        if isinstance(issue_id, str) and _NUMERIC_ID.match(issue_id) and not key:
            again = self._call("GET", f"/rest/api/{self.v}/issue/{_q(issue_id)}?fields=summary")
            key = again.get("key") if isinstance(again, dict) else None
        if not (isinstance(issue_id, str) and _NUMERIC_ID.match(issue_id)
                and isinstance(key, str) and _ISSUE_KEY.match(key)):
            raise JiraHttpError("INVALID", "Jira's search names no valid issue")
        return issue_id, key

    def comment_with(self, key: str, text: str) -> str | None:
        got = self._call("GET", f"/rest/api/{self.v}/issue/{_q(key)}/comment"
                                f"?orderBy=-created&maxResults=20")
        comments = got.get("comments") if isinstance(got, dict) else None
        for comment in comments or []:
            if not isinstance(comment, dict):
                continue
            if text in json.dumps(comment.get("body"), ensure_ascii=False):
                comment_id = comment.get("id")
                if isinstance(comment_id, str) and _NUMERIC_ID.match(comment_id):
                    return comment_id
        return None


# ---------------------------------------------------------------------------
# The route
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class JiraRoute:
    ok: bool
    proxied: bool
    why: str | None
    route: object | None = None

    def as_dict(self) -> dict:
        return {"name": ROUTE, "ok": self.ok, "proxied": self.proxied, "why": self.why}


def _default_route_for():
    from noctornal_api import egress
    return egress.route_for


def route_state(conn, dest_base_url: str, host: str, port: int, *,
                route_for: Callable | None = None) -> JiraRoute:
    """Whether the route "jira" exists and allows host:port. Drafting may
    name any host; Test, activation and every delivery need this."""
    route_for = route_for or _default_route_for()
    network, problem = jira_network()
    if problem is not None:
        return JiraRoute(False, False, problem)
    try:
        declared = (Rule.for_url(dest_base_url, network=network),)
        route = route_for("integration", ROUTE, conn=conn, declared=declared)
    except RouteUnavailable as exc:
        return JiraRoute(False, False, str(exc))
    except (Refusal, ValueError) as exc:
        return JiraRoute(False, False, f"The Jira base URL cannot be used: {exc}.")
    if not route.permits(host, port):
        shown = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        return JiraRoute(False, bool(route.proxied),
                         f"The egress route jira does not allow {shown}. An "
                         f"administrator adds it in Administration, Egress.")
    return JiraRoute(True, bool(route.proxied), None, route)


def route_words(state: JiraRoute) -> str:
    if not state.ok:
        return f"Held: {state.why}"
    if state.proxied:
        return "Through egress route jira, proxied."
    return "Direct: development, the network boundary is not in force."


# ---------------------------------------------------------------------------
# The drain: withdrawal, then the pass
# ---------------------------------------------------------------------------

def withdraw_unroutable(conn: psycopg.Connection) -> int:
    """PENDING JIRA rows nothing may route any more become SUPPRESSED,
    cause WITHDRAWN, with a detail saying which: the destination retired
    (only when NO non-RETIRED destination exists: a destination back in
    DRAFT holds its rows), a kind an administrator
    stopped routing, a case its owner kept out, or a recipient who stopped
    receiving Jira work items. Pausing withdraws
    nothing."""
    dest = conn.execute(
        "SELECT kinds FROM notify.jira_destination WHERE state <> 'RETIRED'").fetchone()
    if dest is None:
        return _withdraw(conn, "true", (),
                         "'the Jira destination was retired after this was queued'")
    kinds = [k for k in (dest[0] or ()) if routable(k)]
    total = _withdraw(conn, "NOT (n.kind = ANY(%s))", (kinds,),
                      "'an administrator stopped routing ' || n.kind "
                      "|| ' to Jira after this was queued'")
    total += _withdraw(conn, """EXISTS (
            SELECT 1 FROM notify.case_route_block b
             WHERE b.case_id = n.case_id AND b.channel = 'JIRA')""", (),
                       "'the case owner kept this case out of Jira after this was queued'")
    total += _withdraw(conn, """NOT coalesce((
            SELECT p.enabled FROM notify.preference p
             WHERE p.user_id = n.recipient_id AND p.channel = 'JIRA'), false)""", (),
                       "'the recipient stopped receiving Jira work items after this "
                       "was queued'")
    return total


def _withdraw(conn, condition: str, params: tuple, detail_sql: str) -> int:
    """One withdrawal. `condition` and `detail_sql` are this module's own
    literals; only `params` carry values."""
    return len(conn.execute(
        f"""UPDATE notify.delivery d
               SET state = 'SUPPRESSED', cause = 'WITHDRAWN', last_attempt_at = now(),
                   detail = {detail_sql}
              FROM notify.notification n
             WHERE n.id = d.notification_id AND d.channel = 'JIRA'
               AND d.state = 'PENDING' AND {condition}
            RETURNING d.id""", params or None).fetchall())


_JIRA_DUE_SQL = """
SELECT d.id, d.notification_id, d.channel, d.attempts,
       n.recipient_id, n.case_id, n.kind, n.priority, n.subject, n.summary,
       n.classification, n.compartments, NULL, c.code,
       n.object_type, n.object_id, n.created_at, coalesce(n.event_id, n.id)
  FROM notify.delivery d
  JOIN notify.notification n ON n.id = d.notification_id
  LEFT JOIN core."case" c ON c.id = n.case_id
 WHERE d.state = 'PENDING' AND d.deliver_after <= now() AND d.channel = 'JIRA'
   AND {readable}
 ORDER BY n.priority ASC, d.deliver_after ASC
 LIMIT %s
"""


def _due(conn, limit: int) -> list:
    from noctornal_api.notifications import readable_predicate
    from noctornal_api.transports import Outgoing

    rows = conn.execute(_JIRA_DUE_SQL.format(readable=readable_predicate("n")),
                        (limit,)).fetchall()
    return [Outgoing(
        delivery_id=r[0], notification_id=r[1], channel=r[2], attempts=r[3],
        recipient_id=r[4], case_id=r[5], kind=r[6], priority=r[7], subject=r[8],
        summary=r[9], classification=r[10], compartments=frozenset(r[11] or []),
        address=None, case_code=r[13], object_type=r[14], object_id=r[15],
        raised_at=r[16], event_id=r[17]) for r in rows]


def count_due(conn) -> int:
    from noctornal_api.notifications import readable_predicate
    return int(conn.execute(
        f"""SELECT count(*) FROM notify.delivery d
              JOIN notify.notification n ON n.id = d.notification_id
             WHERE d.state = 'PENDING' AND d.deliver_after <= now()
               AND d.channel = 'JIRA' AND {readable_predicate('n')}""").fetchone()[0])


def _set_health(conn, dest_id: UUID, health: str, detail: str | None) -> None:
    conn.execute(
        """UPDATE notify.jira_destination
              SET health = %s, health_detail = %s,
                  health_changed_at = CASE WHEN health = %s THEN health_changed_at
                                           ELSE now() END
            WHERE id = %s AND state <> 'RETIRED'""",
        (health, detail, health, dest_id))


def _audit(conn, action: str, *, actor_id: UUID | None, object_type: str,
           object_id: UUID | None, detail: dict, case_id: UUID | None = None,
           actor_kind: str = "USER") -> None:
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id,
                outcome, detail)
           VALUES (%s, %s, %s, %s, %s, %s, 'SUCCESS', %s)""",
        (actor_id, actor_kind, action, object_type, object_id, case_id, Json(detail)))


class _Stop(Exception):
    """The destination changed under the pass: stop, defer the rest."""


class JiraPass:
    """One capped, time-bounded pass over the due JIRA rows (F7).

    Serialised by transports.dispatch_due's session advisory lock, so two
    passes never race for a posting row; the guarded UPDATEs protect
    against the configuration routes (retire, pause) acting mid-pass."""

    def __init__(self, conn: psycopg.Connection, *, client_factory: Callable | None = None,
                 route_for: Callable | None = None, clock: Callable = time.monotonic,
                 limit: int | None = None):
        self._c = conn
        self._factory = client_factory
        self._route_for = route_for
        self._clock = clock
        # Read at call time, so the cap is the module's as it stands.
        self._limit = JIRA_MAX_PER_DRAIN if limit is None else limit
        self._route_obj = None
        self._budget_end = 0.0
        self._status_cache: dict[str, str] = {}
        self.counters = {"sent": 0, "refused": 0, "failed": 0, "held": 0, "deferred": 0}

    # -- the pass -------------------------------------------------------------

    def run(self) -> dict:
        dest = live_destination(self._c)
        if dest is None:
            return self.counters
        due_n = count_due(self._c)
        hold = self._hold_reason(dest)
        if hold is not None:
            self.counters["held"] = due_n
            return self.counters
        route = self._route_obj
        try:
            credential = envelope.decrypt(dest.credential_ciphertext,
                                          key_id=dest.credential_key_id)
        except envelope.UNOPENABLE:
            _set_health(self._c, dest.id, "BROKEN",
                        "the stored credential does not open under the key ring")
            self.counters["held"] = due_n
            return self.counters
        budget_end = self._clock() + JIRA_PASS_SECONDS
        self._budget_end = budget_end
        with pinned_http.secret_in_scope(credential):
            client = self._client(dest, credential, route, budget_end)
            self._reconcile(dest, client)
            rows = _due(self._c, self._limit)
            circuit = False
            for index, out in enumerate(rows):
                if circuit or budget_end - self._clock() < 2.0:
                    self.counters["deferred"] += 1
                    continue
                try:
                    self._still_live(dest)
                except _Stop:
                    self.counters["deferred"] += len(rows) - index
                    break
                try:
                    outcome = self._deliver(dest, client, out)
                except JiraHttpError as exc:
                    self._failed(dest, out, exc)
                    circuit = True
                    continue
                except Exception as exc:  # noqa: BLE001 - one row, never the whole drain
                    # Anything else is an answer this client did not expect,
                    # or a bug: the row records it and the pass stops, so
                    # email, webhooks and the review and escalation producers
                    # after the pass still run (2026-09-25).
                    log.exception("the Jira pass failed on delivery %s", out.delivery_id)
                    self._failed(dest, out, JiraHttpError(
                        "SERVER", f"the Jira pass failed on this delivery "
                        f"({type(exc).__name__}); nothing more was posted this pass"))
                    circuit = True
                    continue
                if outcome == "deferred":
                    self.counters["deferred"] += 1
                elif outcome == "refused":
                    self.counters["refused"] += 1
                else:
                    self.counters["sent"] += 1
        return self.counters

    def _hold_reason(self, dest: Dest) -> str | None:
        """A configuration gap holds and never burns attempts."""
        if dest.state != "ACTIVE":
            return f"the destination is {dest.state}"
        if dest.health == "BROKEN":
            return "the destination is broken"
        if production() and not dest.base_url.startswith("https://"):
            return "the base URL is not https"
        if dest.flavour == "AUTO" or not dest.issue_type_id:
            return "the destination was never tested"
        state = route_state(self._c, dest.base_url, dest.host, dest.port,
                            route_for=self._route_for)
        if not state.ok:
            return state.why
        self._route_obj = state.route
        verdict = envelope.can_open(dest.credential_ciphertext, key_id=dest.credential_key_id)
        if verdict is not None:
            _set_health(self._c, dest.id, "BROKEN",
                        "the stored credential does not open under the key ring")
            return "the credential does not open"
        return None

    def _client(self, dest: Dest, credential: str, route, budget_end: float):
        if self._factory is not None:
            return self._factory(dest=dest, credential=credential, route=route,
                                 budget_end=budget_end, clock=self._clock)
        return JiraClient(dest, credential, route=route, budget_end=budget_end,
                          clock=self._clock)

    def _still_live(self, dest: Dest) -> None:
        row = self._c.execute(
            """SELECT state, updated_at, credential_set_at FROM notify.jira_destination
                WHERE id = %s""", (dest.id,)).fetchone()
        if row is None or row[0] != "ACTIVE" or row[1] != dest.updated_at \
                or row[2] != dest.credential_set_at:
            raise _Stop()

    def _tagged(self, client, delivery_id: UUID):
        route = client.route
        if route is not None and hasattr(route, "tagged") and getattr(route, "context", None) is None:
            client.route = route.tagged(f"delivery:{delivery_id}")
        return route

    # -- one delivery ---------------------------------------------------------

    def _deliver(self, dest: Dest, client, out) -> str:
        from noctornal_api.transports import EGRESS_REFUSED, REFUSED, _succeed

        decision = can_egress(out.classification, Destination.JIRA,
                              compartments=out.compartments,
                              destination_ceiling=effective_ceiling(dest))
        if decision.denied:
            # NOTHING goes to Jira on a refusal, not even a stub issue: a
            # stub is noise in a shared project and still discloses timing.
            _succeed(self._c, out, state=REFUSED, redacted=False,
                     detail=decision.reason, sent_to=None, exposure=None,
                     cause=EGRESS_REFUSED, attempted=False)
            return "refused"
        base_route = self._tagged(client, out.delivery_id)
        try:
            return self._post(dest, client, out)
        finally:
            client.route = base_route

    def _link(self, dest: Dest, out, exposure: str):
        """The open link for this work item, created when there is none.
        A link raised in another project or on another server (the
        destination moved) is closed and never touched again."""
        key = work_key(out, exposure)
        for _ in range(3):
            row = self._c.execute(
                """SELECT id, ref, state, issue_key, issue_id, classification,
                          create_attempted_at, creator_event_id, base_url,
                          project_key,
                          create_attempted_at > now() - %s AS unsettled
                     FROM notify.jira_link
                    WHERE destination_id = %s AND work_key = %s AND state <> 'CLOSED'""",
                (SETTLE, dest.id, key)).fetchone()
            if row is not None:
                if row[8] != dest.base_url or row[9] != dest.project_key:
                    self._c.execute(
                        """UPDATE notify.jira_link SET state = 'CLOSED', closed_at = now(),
                                  closed_reason = 'destination moved'
                            WHERE id = %s AND state <> 'CLOSED'""", (row[0],))
                    continue
                return row
            self._c.execute(
                """INSERT INTO notify.jira_link
                       (destination_id, case_id, work_key, ref, base_url, project_key,
                        classification, exposure)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (destination_id, work_key) WHERE state <> 'CLOSED' DO NOTHING""",
                (dest.id, out.case_id, key, new_ref(), dest.base_url, dest.project_key,
                 out.classification, exposure))
        raise JiraHttpError("INVALID", "could not open a link for this work item")

    def _event(self, link_id: UUID, event_id: UUID):
        return self._c.execute(
            """SELECT state, attempted_at > now() - %s, comment_id, posted_as
                 FROM notify.jira_event WHERE link_id = %s AND event_id = %s""",
            (SETTLE, link_id, event_id)).fetchone()

    def _claim(self, link_id: UUID, event_id: UUID, mark: str, classification: str) -> None:
        self._c.execute(
            """INSERT INTO notify.jira_event
                   (link_id, event_id, marker, state, attempted_at, classification)
               VALUES (%s, %s, %s, 'POSTING', now(), %s)
               ON CONFLICT (link_id, event_id) DO UPDATE SET attempted_at = now()
                WHERE notify.jira_event.state = 'POSTING'""",
            (link_id, event_id, mark, classification))

    def _posted(self, link_id: UUID, event_id: UUID, posted_as: str,
                comment_id: str | None) -> None:
        self._c.execute(
            """UPDATE notify.jira_event
                  SET state = 'POSTED', posted_at = now(), posted_as = %s, comment_id = %s
                WHERE link_id = %s AND event_id = %s AND state = 'POSTING'""",
            (posted_as, comment_id, link_id, event_id))

    def _post(self, dest: Dest, client, out) -> str:
        from noctornal_api.transports import ALREADY_ON_ISSUE, SENT, _succeed

        exposure = dest.field_exposure
        event_id = out.event_id or out.notification_id
        for _attempt in range(2):
            link = self._link(dest, out, exposure)
            link_id, ref, state = link[0], link[1], link[2]
            self._c.execute("UPDATE notify.delivery SET jira_link_id = %s WHERE id = %s",
                            (link_id, out.delivery_id))
            mark = marker(ref, event_id)
            event = self._event(link_id, event_id)
            if event is not None and event[0] == "POSTED":
                if state == "LINKED":
                    _succeed(self._c, out, state=SENT, redacted=False, detail=None,
                             sent_to=browse_url(dest.base_url, link[3], event[2]),
                             exposure=None, cause=ALREADY_ON_ISSUE,
                             jira_link_id=link_id, attempted=False)
                    return "sent"
                # A posted event on a link still CREATING is a create
                # adopted by an earlier pass that has not linked yet.
                return "deferred"
            if event is not None and event[1]:
                return "deferred"   # its outcome is unknown and Jira has not settled
            rendered = render(out, exposure=exposure, api_version=client.v, ref=ref,
                              mark=mark, base=_base_url())
            if state == "CREATING":
                result = self._create(dest, client, out, link, rendered, mark, event_id)
                if result == "comment":
                    continue    # adopted an issue another event created
                return result
            # LINKED
            status = self._status(client, link[3])
            if status in ("done", "NOT_FOUND"):
                self._c.execute(
                    """UPDATE notify.jira_link SET state = 'CLOSED', closed_at = now(),
                              closed_reason = %s
                        WHERE id = %s AND state = 'LINKED'""",
                    ("done in Jira" if status == "done" else "deleted in Jira", link_id))
                continue    # the event goes on a fresh issue
            return self._comment(dest, client, out, link, rendered, mark, event_id)
        return "deferred"

    def _status(self, client, key: str) -> str:
        if key in self._status_cache:
            return self._status_cache[key]
        try:
            status = client.issue_status(key)
        except JiraHttpError as exc:
            if exc.kind != "NOT_FOUND":
                raise
            status = "NOT_FOUND"
        self._status_cache[key] = status
        return status

    def _create(self, dest, client, out, link, rendered, mark, event_id) -> str:
        link_id, ref = link[0], link[1]
        attempted_at, creator, unsettled = link[6], link[7], link[10]
        if attempted_at is not None:
            if unsettled:
                return "deferred"
            found = client.search_ref(dest.project_key, ref)
            if found is not None:
                self._linked(dest, link_id, out.case_id, found, creator or event_id,
                             posted_as="CREATE")
                if creator == event_id:
                    return self._sent_on(dest, out, link_id, found[1], None)
                return "comment"
            moved = self._c.execute(
                """UPDATE notify.jira_link SET create_attempted_at = now(),
                          creator_event_id = %s
                    WHERE id = %s AND state = 'CREATING' AND create_attempted_at = %s
                   RETURNING id""", (event_id, link_id, attempted_at)).fetchone()
            if moved is None:
                return "deferred"
        else:
            took = self._c.execute(
                """UPDATE notify.jira_link SET create_attempted_at = now(),
                          creator_event_id = %s
                    WHERE id = %s AND create_attempted_at IS NULL RETURNING id""",
                (event_id, link_id)).fetchone()
            if took is None:
                return "deferred"
        self._claim(link_id, event_id, mark, out.classification)
        fields = {"project": {"key": dest.project_key},
                  "issuetype": {"id": dest.issue_type_id},
                  "summary": rendered.summary,
                  "description": rendered.description,
                  "labels": list(rendered.labels)}
        try:
            found = client.create_issue(fields)
        except JiraHttpError as exc:
            if exc.kind == "NOT_FOUND":
                # The project itself is gone: a configuration fault.
                raise JiraHttpError("INVALID", "Jira answered 404 to a create: the "
                                    "project or the issue type no longer exists",
                                    status=404) from None
            raise
        self._linked(dest, link_id, out.case_id, found, event_id, posted_as="CREATE")
        self._edit_check(dest, client, found[1])
        return self._sent_on(dest, out, link_id, found[1], None)

    def _linked(self, dest, link_id, case_id, found, event_id, *, posted_as) -> None:
        """LINKED under guard. A link closed underneath (retire) still gets
        the issue key written onto it, so the links list and the purge
        warning can name the issue."""
        issue_id, key = found
        row = self._c.execute(
            """UPDATE notify.jira_link
                  SET state = 'LINKED', issue_key = %s, issue_id = %s, linked_at = now(),
                      last_synced_at = now()
                WHERE id = %s AND state = 'CREATING' RETURNING id""",
            (key, issue_id, link_id)).fetchone()
        if row is None:
            self._c.execute(
                """UPDATE notify.jira_link SET issue_key = %s, issue_id = %s
                    WHERE id = %s AND state = 'CLOSED' AND issue_key IS NULL""",
                (key, issue_id, link_id))
        ref, classification = self._c.execute(
            "SELECT ref, classification FROM notify.jira_link WHERE id = %s",
            (link_id,)).fetchone()
        self._c.execute(
            """INSERT INTO notify.jira_event
                   (link_id, event_id, marker, state, attempted_at, posted_at,
                    posted_as, classification)
               VALUES (%s, %s, %s, 'POSTED', now(), now(), %s, %s)
               ON CONFLICT (link_id, event_id) DO UPDATE
                 SET state = 'POSTED', posted_at = now(), posted_as = EXCLUDED.posted_as
               WHERE notify.jira_event.state = 'POSTING'""",
            (link_id, event_id, marker(ref, event_id), posted_as, classification))
        _audit(self._c, "JIRA_ISSUE_CREATED", actor_id=None, actor_kind="SYSTEM",
               object_type="jira_link", object_id=link_id, case_id=case_id,
               detail={"host": dest.host, "project_key": dest.project_key,
                       "issue_key": key, "exposure": dest.field_exposure})

    def _edit_check(self, dest: Dest, client, key: str) -> None:
        """After a create, whether a later TLP label can be added: the Test
        route can only see the CREATE screen, and editmeta needs an issue.
        A missing labels field is a caveat on the
        destination, never a failure of this delivery."""
        if dest.edit_caveat is not None:
            return
        try:
            allowed = client.edit_labels_allowed(key)
        except JiraHttpError:
            return
        if not allowed:
            self._c.execute(
                "UPDATE notify.jira_destination SET edit_caveat = %s WHERE id = %s",
                (EDIT_SCREEN_CAVEAT, dest.id))

    def _sent_on(self, dest, out, link_id, key, comment_id) -> str:
        from noctornal_api.transports import SENT, _succeed

        self._c.execute("UPDATE notify.jira_link SET last_synced_at = now() WHERE id = %s",
                        (link_id,))
        _succeed(self._c, out, state=SENT, redacted=False, detail=None,
                 sent_to=browse_url(dest.base_url, key, comment_id),
                 exposure=dest.field_exposure, jira_link_id=link_id)
        if dest.health != "OK":
            _set_health(self._c, dest.id, "OK", None)
        return "sent"

    def _comment(self, dest, client, out, link, rendered, mark, event_id) -> str:
        link_id, key, link_class = link[0], link[3], link[5]
        if dest.field_exposure != "STUB" and \
                tlp_from_name(out.classification) > tlp_from_name(link_class):
            # The label goes FIRST: the issue is never left carrying
            # higher-TLP text under a lower label.
            try:
                client.add_label(key, f"tlp-{_label(out.classification)}")
            except JiraHttpError as exc:
                if exc.kind == "INVALID":
                    raise JiraHttpError("INVALID", EDIT_SCREEN_FAULT,
                                        status=exc.status) from None
                raise
            self._c.execute("UPDATE notify.jira_link SET classification = %s WHERE id = %s",
                            (out.classification, link_id))
        event = self._event(link_id, event_id)
        if event is not None and event[0] == "POSTING":
            found = client.comment_with(key, f"NocTORnal ref {mark}")
            if found is not None:
                self._posted(link_id, event_id, "COMMENT", found)
                return self._sent_on(dest, out, link_id, key, found)
        self._claim(link_id, event_id, mark, out.classification)
        comment_id = client.add_comment(key, rendered.comment)
        self._posted(link_id, event_id, "COMMENT", comment_id)
        return self._sent_on(dest, out, link_id, key, comment_id)

    def _failed(self, dest: Dest, out, exc: JiraHttpError) -> None:
        from noctornal_api.transports import RATE_LIMITED, TRANSPORT_ERROR, _fail

        cause = RATE_LIMITED if exc.kind == "RATE_LIMITED" else TRANSPORT_ERROR
        retry = exc.retry_after
        if exc.kind == "RATE_LIMITED" and retry is None:
            retry = RETRY_AFTER_FLOOR_S
        # Redacted again here, inside the pass's secret_in_scope: whatever a
        # client put in its detail, the credential never reaches a row.
        detail = pinned_http.redact(exc.detail)[:500]
        _fail(self._c, out, detail, cause=cause, retry_after=retry)
        self.counters["failed"] += 1
        if exc.kind in CONFIG_FAULTS:
            _set_health(self._c, dest.id, "BROKEN", detail)
        else:
            _set_health(self._c, dest.id, "FAILING", detail)

    # -- reconciliation after an uncertain create ------------------------------

    def _reconcile(self, dest: Dest, client) -> None:
        """Links whose create was attempted and never confirmed, and that no
        pending delivery will come back to (withdrawn by a veto or a
        routing change): search for the issue after SETTLE and record it,
        closing the link when its case is kept out. Needs no deliverable
        row, so an issue about a vetoed case is still found and named."""
        rows = self._c.execute(
            """SELECT l.id, l.ref, l.case_id, l.creator_event_id
                 FROM notify.jira_link l
                WHERE l.destination_id = %s AND l.state = 'CREATING'
                  AND l.create_attempted_at < now() - %s
                  AND NOT EXISTS (SELECT 1 FROM notify.delivery d
                                   WHERE d.jira_link_id = l.id AND d.state = 'PENDING')
                ORDER BY l.create_attempted_at LIMIT %s""",
            (dest.id, SETTLE, RECONCILE_PER_PASS)).fetchall()
        for link_id, ref, case_id, creator in rows:
            if self._budget_end - self._clock() < 2.0:
                return
            try:
                found = client.search_ref(dest.project_key, ref)
            except JiraHttpError:
                return
            except Exception:  # noqa: BLE001 - reconciliation waits for the next pass
                log.exception("the Jira reconciliation search failed")
                return
            if found is None:
                continue
            self._linked(dest, link_id, case_id, found, creator, posted_as="CREATE")
            if case_blocked(self._c, case_id):
                self._c.execute(
                    """UPDATE notify.jira_link SET state = 'CLOSED', closed_at = now(),
                              closed_reason = 'case kept out'
                        WHERE id = %s AND state = 'LINKED'""", (link_id,))


EDIT_SCREEN_CAVEAT = ("The labels field is not on the edit screen for this issue "
                      "type, so a raised TLP marking cannot be added to an existing "
                      "issue. Add it to the edit screen.")
EDIT_SCREEN_FAULT = ("The labels field is not on the edit screen for this issue "
                     "type: a raised TLP marking could not be added to the issue, "
                     "so nothing more was posted on it. Add labels to the edit "
                     "screen, then run Test.")


def _base_url() -> str:
    from noctornal_api.transports import base_url
    return base_url()


# ---------------------------------------------------------------------------
# Administration (F7)
# ---------------------------------------------------------------------------

def _check_base_url(url: str) -> tuple[str, str, int]:
    """(base_url, host, port). https (http only under the development
    flag), no userinfo, query or fragment, no trailing slash."""
    text = (url or "").strip().rstrip("/")
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError:
        raise JiraError("The Jira base URL does not parse as a URL.") from None
    if parts.scheme not in ("https", "http") or (parts.scheme == "http" and not _http_allowed()):
        raise JiraError("The Jira base URL must use https.")
    if parts.username or parts.password or "@" in parts.netloc:
        raise JiraError("The Jira base URL carries a user name or password; the "
                        "credential is entered separately and sealed.")
    if parts.query or parts.fragment or "?" in text or "#" in text:
        raise JiraError("The Jira base URL carries a query or a fragment.")
    try:
        target = split_url(text)
    except Refusal as refusal:
        raise JiraError(f"The Jira base URL cannot be used: {refusal}.") from None
    if not text.isascii():
        raise JiraError("The Jira base URL's host must be written in ASCII (punycode).")
    return text, target.host, target.port


def _check_kinds(kinds) -> list[str]:
    kinds = list(dict.fromkeys(kinds or ()))
    if not kinds:
        raise JiraError("Route at least one kind of notification to Jira.")
    bad = [k for k in kinds if not routable(k)]
    if bad:
        raise JiraError(f"{', '.join(sorted(bad))} cannot be routed to Jira: only the "
                        f"kinds this build names as work items can be.")
    return kinds


def _check_credential(value: str) -> str:
    if not isinstance(value, str) or not 8 <= len(value) <= 4096 \
            or not value.isprintable() or any(ch.isspace() for ch in value):
        raise JiraError("The credential is 8 to 4096 printable characters with no "
                        "spaces or line breaks.")
    return value


def _widened(dest: Dest, ceiling: str, exposure: str, kinds: list[str]) -> bool:
    return (tlp_from_name(ceiling) > tlp_from_name(dest.ceiling)
            or _EXPOSURE_RANK[exposure] > _EXPOSURE_RANK[dest.field_exposure]
            or bool(set(kinds) - set(dest.kinds)))


class JiraAdmin:
    """The destination's configuration routes, one method each."""

    def __init__(self, conn: psycopg.Connection, *, route_for: Callable | None = None,
                 client_factory: Callable | None = None):
        self._c = conn
        self._route_for = route_for
        self._factory = client_factory

    # -- reads ------------------------------------------------------------------

    def view(self) -> dict:
        dest = live_destination(self._c)
        state = (route_state(self._c, dest.base_url, dest.host, dest.port,
                             route_for=self._route_for) if dest else None)
        opted = self._c.execute(
            """SELECT count(*) FROM notify.preference p JOIN iam.app_user u ON u.id = p.user_id
                WHERE p.channel = 'JIRA' AND p.enabled AND u.is_active""").fetchone()[0]
        blocked = self._c.execute(
            "SELECT count(*) FROM notify.case_route_block WHERE channel = 'JIRA'").fetchone()[0]
        return {
            "destination": self.destination_out(dest) if dest else None,
            "route": (state.as_dict() if state else
                      {"name": ROUTE, "ok": False, "proxied": False,
                       "why": "No Jira destination is configured."}),
            "route_words": route_words(state) if state else None,
            "env_ceiling": os.environ.get(CEILING_ENV, "").strip() or None,
            "routable_kinds": {k: KINDS[k].description for k in JIRA_TASKS if k in KINDS},
            "never_kinds": sorted(JIRA_NEVER_KINDS & set(KINDS)),
            "opted_in": int(opted),
            "cases_blocked": int(blocked),
            "exposure_words": EXPOSURE_WORDS,
        }

    def destination_out(self, dest: Dest) -> dict:
        names = self._names([dest.credential_set_by, dest.created_by, dest.updated_by])
        held = self._c.execute(
            """SELECT count(*), min(d.queued_at) FROM notify.delivery d
                WHERE d.channel = 'JIRA' AND d.state = 'PENDING'""").fetchone()
        overdue = self._c.execute(
            """SELECT count(*) FROM notify.delivery d
                WHERE d.channel = 'JIRA' AND d.state = 'PENDING'
                  AND d.deliver_after <= now() - %s""", (OVERDUE_AFTER,)).fetchone()[0]
        return {
            "id": str(dest.id), "label": dest.label, "base_url": dest.base_url,
            "host": dest.host, "port": dest.port, "flavour": dest.flavour,
            "auth_kind": dest.auth_kind, "auth_user": dest.auth_user,
            "credential": {"set": len(dest.credential_ciphertext) > 0,
                           "set_at": dest.credential_set_at.isoformat(),
                           "set_by_name": names.get(dest.credential_set_by)},
            "project_key": dest.project_key, "issue_type": dest.issue_type,
            "issue_type_id": dest.issue_type_id, "ceiling": dest.ceiling,
            "effective_ceiling": effective_ceiling(dest),
            "field_exposure": dest.field_exposure,
            "exposure_words": EXPOSURE_WORDS[dest.field_exposure],
            "kinds": list(dest.kinds), "state": dest.state, "health": dest.health,
            "health_detail": dest.health_detail,
            "health_changed_at": dest.health_changed_at.isoformat()
            if dest.health_changed_at else None,
            "tested_at": dest.tested_at.isoformat() if dest.tested_at else None,
            "server_version": dest.server_version, "deployment_type": dest.deployment_type,
            "edit_caveat": dest.edit_caveat,
            "activated_at": dest.activated_at.isoformat() if dest.activated_at else None,
            "created_at": dest.created_at.isoformat(),
            "created_by_name": names.get(dest.created_by),
            "updated_at": dest.updated_at.isoformat(),
            "updated_by_name": names.get(dest.updated_by),
            "held": int(held[0]),
            "oldest_held_at": held[1].isoformat() if held[1] else None,
            "overdue": int(overdue),
        }

    def _names(self, ids) -> dict:
        rows = self._c.execute(
            "SELECT id, display_name FROM iam.app_user WHERE id = ANY(%s)",
            ([i for i in ids if i],)).fetchall()
        return {r[0]: r[1] for r in rows}

    def _require(self) -> Dest:
        dest = live_destination(self._c)
        if dest is None:
            raise JiraError("No Jira destination is configured.", status=404)
        return dest

    # -- writes -------------------------------------------------------------------

    def create(self, body: dict, *, actor_id: UUID) -> Dest:
        if live_destination(self._c) is not None:
            raise JiraError("A Jira destination is already configured: retire it "
                            "before creating another.", status=409)
        base, host, port = _check_base_url(body.get("base_url", ""))
        flavour = body.get("flavour") or "AUTO"
        auth_kind = body.get("auth_kind")
        if flavour not in FLAVOURS or auth_kind not in AUTH_KINDS:
            raise JiraError("Choose a flavour and an authentication kind this build knows.")
        project = (body.get("project_key") or "").strip()
        if not _PROJECT_KEY.match(project):
            raise JiraError("A Jira project key is 2 to 20 capital letters, digits "
                            "and underscores, starting with a letter.")
        ceiling = body.get("ceiling") or "GREEN"
        exposure = body.get("field_exposure") or "SUBJECT"
        if ceiling not in CEILINGS or exposure not in EXPOSURES:
            raise JiraError("The ceiling is CLEAR, GREEN or AMBER, and the exposure "
                            "STUB, SUBJECT or SUMMARY.")
        kinds = _check_kinds(body.get("kinds") or DEFAULT_KINDS)
        user = body.get("auth_user") if auth_kind != "DC_PAT" else None
        if auth_kind != "DC_PAT" and not (user and user.strip()):
            raise JiraError("This authentication kind needs the account's user name "
                            "or email.")
        credential = _check_credential(body.get("credential"))
        blob, key_id = envelope.encrypt(credential)
        try:
            row = self._c.execute(
                f"""INSERT INTO notify.jira_destination
                       (label, base_url, host, port, flavour, auth_kind, auth_user,
                        credential_ciphertext, credential_key_id, credential_set_by,
                        project_key, issue_type, ceiling, field_exposure, kinds,
                        created_by, updated_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                           %s, %s, %s)
                   RETURNING {_DEST_COLUMNS}""",
                ((body.get("label") or "").strip(), base, host, port, flavour,
                 auth_kind, user.strip() if user else None, blob, key_id, actor_id,
                 project, (body.get("issue_type") or "Task").strip()[:80], ceiling,
                 exposure, kinds, actor_id, actor_id)).fetchone()
        except psycopg.errors.CheckViolation as exc:
            raise JiraError(_check_words(exc)) from None
        except psycopg.errors.UniqueViolation:
            raise JiraError("A Jira destination is already configured.", status=409) from None
        dest = _dest(row)
        _audit(self._c, "JIRA_DESTINATION_CREATED", actor_id=actor_id,
               object_type="jira_destination", object_id=dest.id,
               detail={"host": host, "project_key": project, "flavour": flavour,
                       "ceiling": ceiling, "field_exposure": exposure, "kinds": kinds})
        return dest

    def patch(self, body: dict, *, actor_id: UUID) -> Dest:
        dest = self._require()
        if dest.state == "RETIRED":
            raise JiraError("A retired destination cannot be changed.", status=409)
        changes: dict = {}
        if "label" in body and body["label"] is not None:
            changes["label"] = body["label"].strip()
        if body.get("base_url") is not None:
            base, host, port = _check_base_url(body["base_url"])
            changes.update(base_url=base, host=host, port=port)
        for field_name, allowed in (("flavour", FLAVOURS), ("auth_kind", AUTH_KINDS)):
            if body.get(field_name) is not None:
                if body[field_name] not in allowed:
                    raise JiraError(f"That {field_name.replace('_', ' ')} is not one this "
                                    f"build knows.")
                changes[field_name] = body[field_name]
        if "auth_user" in body:
            changes["auth_user"] = (body["auth_user"] or "").strip() or None
        if body.get("project_key") is not None:
            if not _PROJECT_KEY.match(body["project_key"]):
                raise JiraError("A Jira project key is 2 to 20 capital letters, digits "
                                "and underscores, starting with a letter.")
            changes["project_key"] = body["project_key"]
        if body.get("issue_type") is not None:
            changes["issue_type"] = body["issue_type"].strip()[:80]
        ceiling = body.get("ceiling") or dest.ceiling
        exposure = body.get("field_exposure") or dest.field_exposure
        kinds = _check_kinds(body["kinds"]) if body.get("kinds") is not None else list(dest.kinds)
        if ceiling not in CEILINGS or exposure not in EXPOSURES:
            raise JiraError("The ceiling is CLEAR, GREEN or AMBER, and the exposure "
                            "STUB, SUBJECT or SUMMARY.")
        widened = _widened(dest, ceiling, exposure, kinds)
        if widened and dest.state in ("ACTIVE", "PAUSED"):
            confirm = body.get("confirm") or {}
            if (confirm.get("ceiling") != ceiling or confirm.get("field_exposure") != exposure
                    or sorted(confirm.get("kinds") or []) != sorted(kinds)):
                raise JiraError("Widening what an active destination sends needs the "
                                "same confirmation as activating it.", status=409)
        changes.update(ceiling=ceiling, field_exposure=exposure, kinds=kinds)
        where = {"base_url", "flavour", "auth_kind", "auth_user", "project_key",
                 "issue_type"}
        moved_where = any(k in changes and changes[k] != getattr(dest, k) for k in where)
        moved_links = 0
        if moved_where and dest.state in ("ACTIVE", "PAUSED"):
            changes.update(state="DRAFT", health="UNTESTED")
        if moved_where:
            changes["issue_type_id"] = (None if changes.get("issue_type", dest.issue_type)
                                        != dest.issue_type or "project_key" in changes
                                        else dest.issue_type_id)
        if ("base_url" in changes and changes["base_url"] != dest.base_url) or \
                ("project_key" in changes and changes["project_key"] != dest.project_key):
            # Where the content goes changed: the old issues are closed, so
            # no later event comments on an issue in the project the
            # administrator just moved away from.
            moved_links = len(self._c.execute(
                """UPDATE notify.jira_link SET state = 'CLOSED', closed_at = now(),
                          closed_reason = 'destination moved'
                    WHERE destination_id = %s AND state <> 'CLOSED' RETURNING id""",
                (dest.id,)).fetchall())
        diff = {k: [_plain(getattr(dest, k)), _plain(v)] for k, v in changes.items()
                if _plain(getattr(dest, k)) != _plain(v)}
        if not diff:
            return dest
        sets = ", ".join(f"{k} = %s" for k in changes)
        try:
            row = self._c.execute(
                f"""UPDATE notify.jira_destination SET {sets}, updated_at = now(),
                          updated_by = %s
                     WHERE id = %s RETURNING {_DEST_COLUMNS}""",
                (*changes.values(), actor_id, dest.id)).fetchone()
        except psycopg.errors.CheckViolation as exc:
            raise JiraError(_check_words(exc)) from None
        _audit(self._c, "JIRA_DESTINATION_UPDATED", actor_id=actor_id,
               object_type="jira_destination", object_id=dest.id,
               detail={"changed": diff, "widened": widened, "links_closed": moved_links})
        return _dest(row)

    def set_credential(self, credential: str, *, actor_id: UUID) -> Dest:
        dest = self._require()
        blob, key_id = envelope.encrypt(_check_credential(credential))
        row = self._c.execute(
            f"""UPDATE notify.jira_destination
                   SET credential_ciphertext = %s, credential_key_id = %s,
                       credential_set_at = now(), credential_set_by = %s,
                       health = 'UNTESTED', health_detail = NULL,
                       health_changed_at = now(), updated_at = now(), updated_by = %s
                 WHERE id = %s RETURNING {_DEST_COLUMNS}""",
            (blob, key_id, actor_id, actor_id, dest.id)).fetchone()
        _audit(self._c, "JIRA_CREDENTIAL_SET", actor_id=actor_id,
               object_type="jira_destination", object_id=dest.id, detail={})
        return _dest(row)

    def test(self, *, actor_id: UUID) -> dict:
        """Route, serverInfo, flavour, auth, project, issue type and the
        labels field. Creates nothing and sends no case text."""
        dest = self._require()
        steps: list[dict] = []

        def step(name: str, ok: bool, evidence: str) -> bool:
            steps.append({"step": name, "ok": ok, "evidence": evidence})
            return ok

        updates: dict = {}
        ok = self._test_steps(dest, step, updates)
        health = "OK" if ok else "BROKEN"
        detail = None if ok else next((s["evidence"] for s in steps if not s["ok"]), None)
        values = dict(updates, tested_at=datetime.now(timezone.utc) if ok else dest.tested_at,
                      health=health, health_detail=detail)
        sets = ", ".join(f"{k} = %s" for k in values)
        self._c.execute(
            f"""UPDATE notify.jira_destination SET {sets}, health_changed_at = now()
                 WHERE id = %s""", (*values.values(), dest.id))
        _audit(self._c, "JIRA_DESTINATION_TESTED", actor_id=actor_id,
               object_type="jira_destination", object_id=dest.id,
               detail={"ok": ok, "failed_step": next((s["step"] for s in steps
                                                       if not s["ok"]), None)})
        return {"ok": ok, "steps": steps}

    def _test_steps(self, dest: Dest, step, updates: dict) -> bool:
        if production() and not dest.base_url.startswith("https://"):
            return step("route", False, "The base URL is not https, and production "
                        "sends to Jira over https only.")
        state = route_state(self._c, dest.base_url, dest.host, dest.port,
                            route_for=self._route_for)
        if not step("route", state.ok, route_words(state)):
            return False
        try:
            credential = envelope.decrypt(dest.credential_ciphertext,
                                          key_id=dest.credential_key_id)
        except envelope.UNOPENABLE:
            return step("credential", False, "The stored credential does not open "
                        "under the key ring; enter it again.")
        clock = time.monotonic
        budget = clock() + TEST_SECONDS
        with pinned_http.secret_in_scope(credential):
            route = state.route.tagged(f"check:{uuid5(NAMESPACE_URL, str(dest.id))}") \
                if hasattr(state.route, "tagged") else state.route
            make = self._factory or (lambda **kw: JiraClient(
                kw["dest"], kw["credential"], route=kw["route"],
                budget_end=kw["budget_end"], clock=kw["clock"]))
            client = make(dest=dest, credential=credential, route=route,
                          budget_end=budget, clock=clock)
            try:
                deployment, version = client.server_info()
            except JiraHttpError as exc:
                return step("connect", False, exc.detail)
            flavour_found = _DEPLOYMENT_TYPES[deployment]
            step("connect", True, f"Jira {deployment}"
                 + (f" {version}" if version else "") + " answered over a verified connection.")
            updates.update(server_version=version, deployment_type=deployment)
            fits = (flavour_found != "CLOUD" or dest.auth_kind == "CLOUD_API_TOKEN") and \
                   (flavour_found != "DATA_CENTER" or dest.auth_kind in ("DC_PAT", "DC_BASIC"))
            if not fits:
                return step("auth_kind", False,
                            f"This is Jira {'Cloud' if flavour_found == 'CLOUD' else 'Data Center'}, "
                            f"and {dest.auth_kind} is not a way to sign in to it.")
            if dest.flavour != "AUTO" and dest.flavour != flavour_found:
                return step("flavour", False, f"The destination says {dest.flavour} and "
                            f"the server is {flavour_found}.")
            step("flavour", True, flavour_found)
            updates["flavour"] = flavour_found
            client.v = 3 if flavour_found == "CLOUD" else 2
            try:
                who = client.myself()
            except JiraHttpError as exc:
                return step("auth", False, exc.detail)
            step("auth", True, f"Signed in as {who}.")
            try:
                client.project(dest.project_key)
            except JiraHttpError as exc:
                return step("project", False, exc.detail)
            step("project", True, f"Project {dest.project_key} is visible.")
            try:
                types = client.issue_types(dest.project_key)
            except JiraHttpError as exc:
                return step("issue_type", False, exc.detail)
            match = next((tid for tid, name in types
                          if name.lower() == dest.issue_type.lower()), None)
            if match is None:
                return step("issue_type", False, f"The issue type {dest.issue_type} is not "
                            f"on project {dest.project_key}.")
            step("issue_type", True, f"{dest.issue_type} found.")
            updates["issue_type_id"] = match
            try:
                fields = client.issue_type_fields(dest.project_key, match)
            except JiraHttpError as exc:
                return step("labels_field", False, exc.detail)
            if "labels" not in fields:
                return step("labels_field", False,
                            "The labels field is not on the create screen for this issue "
                            "type. Add it, or choose another issue type: NocTORnal marks "
                            "its issues with a label so a retry never makes a second one.")
            step("labels_field", True, "The labels field is on the create screen.")
        return True

    def activate(self, confirm: dict, *, actor_id: UUID, resume: bool = False) -> Dest:
        dest = self._require()
        if resume:
            if dest.state != "PAUSED":
                raise JiraError("Only a paused destination can be resumed.", status=409)
        elif dest.state not in ("DRAFT", "PAUSED"):
            raise JiraError("Only a drafted or paused destination can be activated.",
                            status=409)
        if not resume and (confirm.get("ceiling") != dest.ceiling
                           or confirm.get("field_exposure") != dest.field_exposure
                           or sorted(confirm.get("kinds") or []) != sorted(dest.kinds)):
            raise JiraError("The confirmation was for a different configuration. Read it "
                            "again before activating.", status=409)
        if dest.health != "OK" or dest.tested_at is None or \
                datetime.now(timezone.utc) - dest.tested_at > TEST_FRESH_FOR:
            raise JiraError("Run Test first: activation needs a passing test from the "
                            "last 24 hours.", status=409)
        state = route_state(self._c, dest.base_url, dest.host, dest.port,
                            route_for=self._route_for)
        if not state.ok:
            raise JiraError(state.why or "The egress route jira is not usable.", status=409)
        row = self._c.execute(
            f"""UPDATE notify.jira_destination
                   SET state = 'ACTIVE', activated_at = now(), updated_at = now(),
                       updated_by = %s
                 WHERE id = %s RETURNING {_DEST_COLUMNS}""",
            (actor_id, dest.id)).fetchone()
        _audit(self._c, "JIRA_DESTINATION_RESUMED" if resume else "JIRA_DESTINATION_ACTIVATED",
               actor_id=actor_id, object_type="jira_destination", object_id=dest.id,
               detail={"host": dest.host, "project_key": dest.project_key,
                       "flavour": dest.flavour, "ceiling": dest.ceiling,
                       "field_exposure": dest.field_exposure, "kinds": list(dest.kinds),
                       "proxied": state.proxied})
        return _dest(row)

    def pause(self, *, actor_id: UUID) -> Dest:
        dest = self._require()
        if dest.state != "ACTIVE":
            raise JiraError("Only an active destination can be paused.", status=409)
        row = self._c.execute(
            f"""UPDATE notify.jira_destination SET state = 'PAUSED', updated_at = now(),
                       updated_by = %s WHERE id = %s RETURNING {_DEST_COLUMNS}""",
            (actor_id, dest.id)).fetchone()
        _audit(self._c, "JIRA_DESTINATION_PAUSED", actor_id=actor_id,
               object_type="jira_destination", object_id=dest.id, detail={})
        return _dest(row)

    def retire(self, *, actor_id: UUID) -> dict:
        dest = self._require()
        with self._c.transaction():
            self._c.execute(
                """UPDATE notify.jira_destination
                      SET state = 'RETIRED', retired_at = now(),
                          credential_ciphertext = ''::bytea, credential_key_id = NULL,
                          updated_at = now(), updated_by = %s
                    WHERE id = %s""", (actor_id, dest.id))
            closed = len(self._c.execute(
                """UPDATE notify.jira_link SET state = 'CLOSED', closed_at = now(),
                          closed_reason = 'destination retired'
                    WHERE destination_id = %s AND state <> 'CLOSED' RETURNING id""",
                (dest.id,)).fetchall())
            _audit(self._c, "JIRA_DESTINATION_RETIRED", actor_id=actor_id,
                   object_type="jira_destination", object_id=dest.id,
                   detail={"links_closed": closed})
        return {"retired": str(dest.id), "links_closed": closed}

    def links(self, *, case_id: UUID | None, state: str | None, limit: int,
              before: str | None, actor_id: UUID) -> dict:
        """The issues NocTORnal made, newest first. The case is never named
        and no classification is returned:
        case_id is a filter the caller supplies, and a filtered read is
        audited because it tells an administrator whether a given case
        reached Jira."""
        clauses, params = ["true"], []
        if case_id is not None:
            clauses.append("l.case_id = %s")
            params.append(case_id)
        if state:
            clauses.append("l.state = %s")
            params.append(state)
        if before:
            at, link_id = _cursor(before)
            clauses.append("(l.created_at, l.id) < (%s, %s)")
            params += [at, link_id]
        rows = self._c.execute(
            f"""SELECT l.id, l.issue_key, l.base_url, l.state, l.exposure, l.created_at,
                       l.last_synced_at, l.ref, l.create_attempted_at, l.closed_reason,
                       (SELECT count(*) FROM notify.jira_event e WHERE e.link_id = l.id
                         AND e.state = 'POSTED')
                  FROM notify.jira_link l
                 WHERE {' AND '.join(clauses)}
                 ORDER BY l.created_at DESC, l.id DESC LIMIT %s""",
            (*params, limit + 1)).fetchall()
        more = len(rows) > limit
        rows = rows[:limit]
        if case_id is not None:
            _audit(self._c, "JIRA_LINKS_READ", actor_id=actor_id, object_type="case",
                   object_id=case_id, case_id=case_id, detail={"count": len(rows)})
        return {"links": [{
            "id": str(r[0]), "issue_key": r[1],
            "browse_url": browse_url(r[2], r[1]) if r[1] else None,
            "state": r[3], "exposure": r[4], "created_at": r[5].isoformat(),
            "last_synced_at": r[6].isoformat() if r[6] else None,
            # The ref label, so an operator can find an unconfirmed create
            # by JQL.
            "ref_label": f"noctornal-ref-{r[7]}" if r[8] is not None and not r[1] else None,
            "closed_reason": r[9], "events": int(r[10])} for r in rows],
            "next": _make_cursor(rows[-1][5], rows[-1][0]) if more and rows else None}


def _plain(value):
    if isinstance(value, (tuple, list)):
        return list(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    return value


def _check_words(exc: psycopg.errors.CheckViolation) -> str:
    name = getattr(getattr(exc, "diag", None), "constraint_name", None) or ""
    words = {
        "jira_destination_below_floor": "The ceiling is CLEAR, GREEN or AMBER: "
                                        "nothing above AMBER ever leaves the platform.",
        "jira_destination_auth_matches": "That authentication kind does not fit that "
                                         "flavour of Jira.",
        "jira_destination_auth_user": "A personal access token takes no user name; the "
                                      "other kinds need one.",
        "jira_destination_label_present": "The label is 1 to 80 characters.",
        "jira_destination_kinds_present": "Route at least one kind to Jira.",
    }
    return words.get(name, "That configuration is not one Jira destinations allow.")


def _make_cursor(at: datetime, row_id: UUID) -> str:
    raw = f"{at.isoformat()}|{row_id}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _cursor(text: str) -> tuple[datetime, UUID]:
    try:
        padded = text + "=" * (-len(text) % 4)
        at, _, row_id = base64.urlsafe_b64decode(padded.encode("ascii")).decode(
            "utf-8").partition("|")
        return datetime.fromisoformat(at), UUID(row_id)
    except (ValueError, UnicodeError):
        raise JiraError("That page cursor is not one this server issued.") from None


# ---------------------------------------------------------------------------
# The case owner's veto (F7)
# ---------------------------------------------------------------------------

def case_routing(conn: psycopg.Connection, case_id: UUID, *, clearance: str) -> dict:
    """The veto and the issues already raised. The count is of the links
    the reader is cleared for: a reader below a link's marking is not told
    that an issue exists about it (2026-09-25; links carry
    no compartments, because compartmented material never reaches Jira)."""
    row = conn.execute(
        """SELECT b.reason, u.display_name, b.blocked_at
             FROM notify.case_route_block b JOIN iam.app_user u ON u.id = b.blocked_by
            WHERE b.case_id = %s AND b.channel = 'JIRA'""", (case_id,)).fetchone()
    dest = live_destination(conn)
    issues = conn.execute(
        "SELECT count(*) FROM notify.jira_link WHERE case_id = %s "
        "AND classification <= %s::core.tlp", (case_id, clearance)).fetchone()[0]
    return {"jira": {
        "blocked": row is not None, "reason": row[0] if row else None,
        "blocked_by_name": row[1] if row else None,
        "blocked_at": row[2].isoformat() if row else None,
        "destination": ({"state": dest.state, "host": dest.host,
                         "project_key": dest.project_key} if dest else None),
        "issues": int(issues)}}


def set_case_routing(conn: psycopg.Connection, case_id: UUID, *, blocked: bool,
                     reason: str | None, actor_id: UUID, clearance: str = "CLEAR") -> dict:
    """A block takes effect at queue time (CASE_NOT_ROUTED) and, for rows
    already queued, at the next drain (WITHDRAWN). Allowed whether or not
    Jira is configured, so an owner can keep a case out before anyone
    activates it. The answer counts the issues already raised about the
    case: a veto does not reach back into Jira."""
    if blocked:
        text = (reason or "").strip()
        if not 5 <= len(text) <= 500:
            raise JiraError("Say why, in 5 to 500 characters: the case trail keeps it.")
        conn.execute(
            """INSERT INTO notify.case_route_block (case_id, channel, reason, blocked_by)
               VALUES (%s, 'JIRA', %s, %s)
               ON CONFLICT (case_id, channel) DO UPDATE SET reason = EXCLUDED.reason""",
            (case_id, text, actor_id))
    else:
        text = None
        conn.execute("DELETE FROM notify.case_route_block WHERE case_id = %s "
                     "AND channel = 'JIRA'", (case_id,))
    _audit(conn, "NOTIFY_CASE_ROUTING_CHANGED", actor_id=actor_id, object_type="case",
           object_id=case_id, case_id=case_id,
           detail={"channel": "JIRA", "blocked": blocked, "reason": text})
    return case_routing(conn, case_id, clearance=clearance)


# ---------------------------------------------------------------------------
# Retention (F7)
# ---------------------------------------------------------------------------

def purge_note(conn: psycopg.Connection, case_ids, *, actor_id: UUID | None,
               dry_run: bool) -> str | None:
    """A purge deletes nothing in Jira. When the cases it touched have
    issues there, say so with the count and the host, and on a real purge
    record it (JIRA_ISSUES_OUTLIVE_PURGE)."""
    ids = [c for c in dict.fromkeys(case_ids or []) if c is not None]
    if not ids:
        return None
    rows = conn.execute(
        """SELECT count(*), count(DISTINCT l.case_id), min(d.host)
             FROM notify.jira_link l JOIN notify.jira_destination d ON d.id = l.destination_id
            WHERE l.case_id = ANY(%s)""", (ids,)).fetchone()
    n, cases, host = int(rows[0]), int(rows[1]), rows[2]
    if not n:
        return None
    if not dry_run:
        _audit(conn, "JIRA_ISSUES_OUTLIVE_PURGE", actor_id=actor_id,
               object_type="purge", object_id=None,
               detail={"cases": cases, "issues": n, "host": host})
    return (f"{count_of(n, 'Jira issue', 'Jira issues')} on {host} "
            f"{agree(n, 'was', 'were')} raised about the cases this purge touched. "
            f"NocTORnal cannot delete {agree(n, 'it', 'them')}: Administration, "
            f"Integrations lists them by case.")


def readiness_verdict(conn: psycopg.Connection, *, route_for: Callable | None = None):
    """(ok, evidence, action, caveat) for the jira_destination readiness row
    (F7)."""
    dest = live_destination(conn)
    if dest is None:
        return True, "No Jira destination is configured, so nothing is sent to Jira.", "", ""
    held = conn.execute(
        """SELECT count(*), min(queued_at) FROM notify.delivery
            WHERE channel = 'JIRA' AND state = 'PENDING'""").fetchone()
    held_n, oldest = int(held[0]), held[1]
    held_words = count_of(held_n, "delivery", "deliveries")
    if dest.state == "DRAFT":
        caveat = "drafted, not active: nothing is sent until it is tested and activated"
        if held_n:
            caveat += (f"; {held_words} held, the oldest queued "
                       f"{oldest:%Y-%m-%d %H:%M} UTC")
        return True, f"Jira destination {dest.label} on {dest.host}.", "", caveat
    state = route_state(conn, dest.base_url, dest.host, dest.port, route_for=route_for)
    if not state.ok:
        return (False, f"{state.why} {held_words} waiting.",
                f"add {dest.host}:{dest.port} to the jira route in Administration, Egress",
                "")
    verdict = envelope.can_open(dest.credential_ciphertext, key_id=dest.credential_key_id)
    if verdict is not None:
        return (False, f"The Jira credential does not open under key "
                f"{dest.credential_key_id or envelope.DEFAULT_KEY_ID}.",
                "enter the Jira credential again in Administration, Integrations", "")
    since = (f"{dest.health_changed_at:%Y-%m-%d %H:%M} UTC" if dest.health_changed_at
             else "an unrecorded time")
    if dest.health == "BROKEN":
        return (False, f"Broken since {since}: {dest.health_detail}. {held_words} held.",
                "Fix the destination in Administration, Integrations, then run Test.", "")
    if dest.health == "FAILING":
        return (False, f"Jira has been failing since {since}: {dest.health_detail}; "
                f"{held_words} waiting.",
                "Check Jira is up and answering; deliveries retry on their own.", "")
    if dest.state == "PAUSED":
        caveat = "paused"
        if held_n:
            caveat += (f": {held_words} held, the oldest queued "
                       f"{oldest:%Y-%m-%d %H:%M} UTC")
        return True, f"Jira destination {dest.label} on {dest.host} is paused.", "", caveat
    overdue = conn.execute(
        """SELECT count(*), min(deliver_after) FROM notify.delivery
            WHERE channel = 'JIRA' AND state = 'PENDING'
              AND deliver_after <= now() - %s""", (OVERDUE_AFTER,)).fetchone()
    recent = conn.execute(
        """SELECT EXISTS (SELECT 1 FROM notify.delivery WHERE channel = 'JIRA'
                           AND last_attempt_at > now() - %s)""",
        (OVERDUE_AFTER,)).fetchone()[0]
    opted = conn.execute(
        """SELECT count(*) FROM notify.preference p JOIN iam.app_user u ON u.id = p.user_id
            WHERE p.channel = 'JIRA' AND p.enabled AND u.is_active""").fetchone()[0]
    blocked = conn.execute(
        "SELECT count(*) FROM notify.case_route_block WHERE channel = 'JIRA'").fetchone()[0]
    evidence = (f"{dest.host}, project {dest.project_key}, {dest.flavour}"
                + (f" {dest.server_version}" if dest.server_version else "")
                + f", ceiling {effective_ceiling(dest)}, "
                f"{EXPOSURE_WORDS[dest.field_exposure]} Tested "
                + (f"{dest.tested_at:%Y-%m-%d %H:%M} UTC" if dest.tested_at else "never")
                + f"; {count_of(int(opted), 'person receives', 'people receive')} "
                f"Jira work items; {count_of(int(blocked), 'case is', 'cases are')} kept "
                f"out; {route_words_evidence(state)}.")
    if int(overdue[0]):
        n = int(overdue[0])
        if not recent:
            # Only when nothing has been sent or tried for as long as the
            # backlog is late: a resumed backlog draining at fifty a pass
            # is not a stopped drain.
            return (False, f"{count_of(n, 'Jira delivery is', 'Jira deliveries are')} "
                    f"overdue and nothing is failing: no drain is reaching them.",
                    "Start the cron service, or run python scripts/notify_drain.py; "
                    "Drain now in Administration, Integrations runs one pass.", "")
        return (True, evidence, "",
                f"{count_of(n, 'Jira delivery is', 'Jira deliveries are')} draining, "
                f"the oldest due {overdue[1]:%Y-%m-%d %H:%M} UTC")
    caveat = "credential replaced, not yet tested" if dest.health == "UNTESTED" else ""
    if dest.edit_caveat:
        caveat = (caveat + "; " if caveat else "") + dest.edit_caveat
    return True, evidence, "", caveat


def route_words_evidence(state: JiraRoute) -> str:
    return ("through egress route jira, proxied" if state.proxied
            else "direct (development: the network boundary is not in force)")


__all__ = ["JiraPass", "JiraAdmin", "JiraClient", "JiraHttpError", "JiraError",
           "routing", "routable", "withdraw_unroutable", "render", "work_key",
           "marker", "purge_note", "case_routing", "set_case_routing"]
