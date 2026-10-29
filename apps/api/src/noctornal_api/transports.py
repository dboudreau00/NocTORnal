"""Outbound transports: SMTP and HMAC-signed webhooks, and the outbox drain that feeds them.

Jira's pass lives in `jira.py` and runs from here. Every function here calls `egress.can_egress()`
before it sends anything (invariant 8, docs/07): integrations are the leak path in every system of
this kind, because a ticket or mail quietly copies intelligence into a system with a different
access model and a wider audience.

Email content rules (docs/07): the subject line carries no intelligence and the body carries a
summary and a deep link, not the content. `render_email()` is the only function that builds an
email and reads `subject` and `summary` only, never `body`; a test patches the column out and
checks the mail still renders.

Content that cannot leave is not silently dropped or downgraded. The delivery row is written
`REFUSED` with the gate's reason code and, when the recipient would otherwise get nothing, a stub
goes out: the fact that something is waiting, with no case content and no case code. The full
notification stays in the centre behind the access gate.

Deep links carry no token. A single-use token in an email is a bearer credential in the least
trustworthy channel, so the link is a plain URL to the login page. Any future deep link must be
scoped to navigation only, never to access.

The egress proxy is the only way out in production (docs/00 decision 68). Every integration takes
its route from `egress.route_for`: SMTP uses the route "smtp" through `pinned_http.open_connection`
and webhooks use "webhook" through `pinned_http.fetch_response`, never urllib (it honours
HTTP(S)_PROXY, follows redirects as a bodiless GET and accepts http://). A configuration gap HOLDS
a delivery: a channel whose route is missing or does not allow its endpoint is not drained, its due
rows stay PENDING with attempts untouched and are counted as `held`. Only an attempted send FAILS.

Every decided row carries a stable `cause` (CAUSES below) beside the human `detail`, and every row
that left the building carries its `exposure` (STUB, SUBJECT or SUMMARY). Code matches on the
cause, never the sentence.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import smtplib
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Callable
from uuid import UUID

import psycopg

from noctornal_api import pinned_http
from noctornal_api.config import is_production
from noctornal_api.egress import Destination, can_egress
from noctornal_api.egress_policy import Refusal, Rule, split_url
from noctornal_api.notifications import (
    JIRA,
    REFUSED,
    SENT,
    SMTP,
    WEBHOOK,
    deliverable_predicate,
    element_rows_sql,
    escalate_unacknowledged,
    single_address_domain,
)
from noctornal_api.notify_events import case_reviews_due

log = logging.getLogger("noctornal.transports")

# A runaway loop must not fire ten thousand emails (docs/07). Applied per
# drain rather than per hour: the drain is the only thing that sends, so
# bounding it bounds the blast radius of any producer.
MAX_PER_DRAIN = 200
# After this many failures a delivery stops being retried and stays FAILED.
# A permanently-retried delivery is a permanently-hot outbox.
MAX_ATTEMPTS = 5

#: Serialises the whole drain across processes (see `dispatch_due`).
#:
#: Session-scoped (`pg_try_advisory_lock`) because `db.connect()` is autocommit: a transaction-scoped
#: lock would be released by the statement that took it. The name is hashed with
#: `hashtextextended(..., 0)`, as migrations 0013 and 0024 do for the audit and custody chains.
_DRAIN_LOCK = "notify.dispatch_due"

PRODUCT = "NocTORnal"

#: The integration route names (egress.INTEGRATIONS registers them).
ROUTE_SMTP = "smtp"
ROUTE_WEBHOOK = "webhook"
#: One SMTP session, banner to QUIT, through one entered Deadline
#: (docs/20 section 9: the drain enters one per message).
SMTP_SEND_SECONDS = 60.0
WEBHOOK_SECONDS = 15.0
WEBHOOK_USER_AGENT = "NocTORnal-webhook/1"
WEBHOOK_MAX_BYTES = 65536
#: http:// for the webhook, development only. Refused in config in production, and refused at send
#: time in production whatever it says: the cron sends, and the cron never ran verify_environment.
WEBHOOK_ALLOW_HTTP_ENV = "NOCTORNAL_WEBHOOK_ALLOW_HTTP"

#: Which signature scheme the webhook destination speaks. Unset or `v1`: `X-NocTORnal-Signature:
#: sha256=<hex>`, an HMAC-SHA256 over the exact body, with no time. `v2` is opt-in:
#: `X-NocTORnal-Signature-V2: t=<unix seconds>,v2=<hex>`, an HMAC-SHA256 over `<t>.<body>`. The format
#: and a receiver's replay rules are in docs/07.
WEBHOOK_SIGNATURE_ENV = "NOCTORNAL_WEBHOOK_SIGNATURE"
WEBHOOK_SECRET_ENV = "NOCTORNAL_WEBHOOK_SECRET"
SIGNATURE_V1 = "v1"
SIGNATURE_V2 = "v2"
SIGNATURE_HEADER = "X-NocTORnal-Signature"
SIGNATURE_HEADER_V2 = "X-NocTORnal-Signature-V2"

RECIPIENT_DISABLED = "RECIPIENT_DISABLED"
BELOW_THRESHOLD = "BELOW_THRESHOLD"
CASELESS = "CASELESS"
DESTINATION_OFF = "DESTINATION_OFF"
KIND_NOT_ROUTED = "KIND_NOT_ROUTED"
CASE_NOT_ROUTED = "CASE_NOT_ROUTED"
WITHDRAWN = "WITHDRAWN"
REVOKED = "REVOKED"
EGRESS_REFUSED = "EGRESS_REFUSED"
TRANSPORT_ERROR = "TRANSPORT_ERROR"
RATE_LIMITED = "RATE_LIMITED"
GAVE_UP = "GAVE_UP"
REQUEUED = "REQUEUED"
ALREADY_ON_ISSUE = "ALREADY_ON_ISSUE"
LEGACY = "LEGACY"

#: Every cause, in one place (0095's CHECK spells the same list and a test
#: holds the two equal).
CAUSES: tuple[str, ...] = (
    RECIPIENT_DISABLED, BELOW_THRESHOLD, CASELESS, DESTINATION_OFF,
    KIND_NOT_ROUTED, CASE_NOT_ROUTED, WITHDRAWN, REVOKED, EGRESS_REFUSED,
    TRANSPORT_ERROR, RATE_LIMITED, GAVE_UP, REQUEUED, ALREADY_ON_ISSUE, LEGACY)

#: The server's sentence for each cause: the console renders it as sent and
#: duplicates none of it.
CAUSE_TEXT: dict[str, str] = {
    RECIPIENT_DISABLED: "The recipient turned this channel off.",
    BELOW_THRESHOLD: "Below the recipient's minimum priority for this channel.",
    CASELESS: "Jira takes work items about a case, and this notification concerns none.",
    DESTINATION_OFF: "No Jira destination was active when this was raised.",
    KIND_NOT_ROUTED: "An administrator has not routed this kind to Jira.",
    CASE_NOT_ROUTED: "The case owner keeps this case's notifications out of Jira.",
    WITHDRAWN: "Queued, then withdrawn before it went: the detail says why.",
    REVOKED: "The recipient may no longer read it: clearance, compartments or "
             "case assignment changed after it was queued.",
    EGRESS_REFUSED: "The egress gate refused the content.",
    TRANSPORT_ERROR: "The send failed and is backing off before the next attempt.",
    RATE_LIMITED: "The far end asked to slow down; the next attempt waits for it.",
    GAVE_UP: "Every attempt failed, so the delivery stopped being retried.",
    REQUEUED: "An administrator put it back in the outbox.",
    ALREADY_ON_ISSUE: "Another recipient's delivery of the same event already put "
                      "it on the Jira issue.",
    LEGACY: "Suppressed before the ledger recorded causes.",
}

#: What the gate said, per reason code, naming no level: the ledger's
#: reader holds integration.manage, which is not a clearance, and
#: EgressDecision.explain() would tell them which rows carried RED rather
#: than AMBER_STRICT material.
GATE_TEXT: dict[str, str] = {
    "above_platform_floor": "The content's marking never leaves this platform, "
                            "whatever the destination accepts.",
    "above_destination_ceiling": "The content is marked above what this "
                                 "destination is cleared to hold.",
    "compartmented_material": "Compartmented material never leaves the platform: "
                              "no outside system models compartments.",
}
GATE_FALLBACK = ("The gate could not read the marking or the destination's "
                 "ceiling, so it refused rather than guess.")

#: What left, in words, for the console's chip (`left`).
EXPOSURES = ("STUB", "SUBJECT", "SUMMARY")


def cause_text(cause: str | None, *, channel: str, detail: str | None,
               exposure: str | None) -> str | None:
    """The sentence for a row: the cause's, and for an egress refusal the
    gate's reason in words and what went instead."""
    if cause is None:
        return None
    if cause == EGRESS_REFUSED:
        gate = GATE_TEXT.get(detail or "", GATE_FALLBACK)
        instead = (" A content-free stub went out instead." if exposure == "STUB"
                   else " Nothing was sent.")
        return gate + instead
    return CAUSE_TEXT.get(cause)


class TransportError(Exception):
    """A send that was attempted and did not complete. `retry_after` is
    the far end's Retry-After in seconds, when it gave one; `cause` is
    RATE_LIMITED for a 429 and TRANSPORT_ERROR otherwise."""

    def __init__(self, message: str, *, retry_after: float | None = None,
                 cause: str = TRANSPORT_ERROR):
        super().__init__(message)
        self.retry_after = retry_after
        self.cause = cause


@dataclass(frozen=True)
class Outgoing:
    """One due delivery, joined to the notification it belongs to.

    The four fields after `case_code` are Jira's and are declared last with defaults, so existing
    keyword constructors keep working. It carries no body (decision 46).
    """

    delivery_id: UUID
    notification_id: UUID
    channel: str
    attempts: int
    recipient_id: UUID
    case_id: UUID | None
    kind: str
    priority: int
    subject: str
    summary: str
    classification: str
    compartments: frozenset[str]
    address: str | None
    case_code: str | None
    object_type: str | None = None
    object_id: UUID | None = None
    raised_at: datetime | None = None
    event_id: UUID | None = None


def base_url() -> str:
    """Where a link in an email points. No default with a real hostname in
    it: a wrong link in an email is a support ticket, and a link to somebody
    else's deployment is worse."""
    return os.environ.get("NOCTORNAL_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


def production() -> bool:
    """config's reading of NOCTORNAL_ENV: the one reader of the mode."""
    return is_production()


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_email(out: Outgoing, *, redacted: bool) -> EmailMessage:
    """Build the message.

    Reads `subject` and `summary`. Deliberately has no access to the
    notification body at all -- `Outgoing` does not carry it, so the rule is
    enforced by the shape of the data rather than by the author remembering.

    `redacted=True` is the stub: something is waiting, nothing about what.
    """
    message = EmailMessage()
    if redacted:
        # No case code either. A case code IS intelligence -- "OP-KESTREL"
        # on a phone lock screen tells a shoulder-surfer that an operation
        # by that name exists and that this person works on it.
        message["Subject"] = f"[{PRODUCT}] You have a notification"
        text = (
            f"There is a notification waiting for you in {PRODUCT}.\n\n"
            f"Its content is classified above what may be sent by email, so\n"
            f"none of it appears here. Sign in to read it.\n\n"
            f"    {base_url()}/ui/\n\n"
            f"-- \nThis message contains no case material.\n"
        )
    else:
        message["Subject"] = f"[{PRODUCT}] {out.subject}"
        text = (
            f"{out.summary}\n\n"
            f"Sign in to read the detail:\n\n"
            f"    {base_url()}/ui/\n\n"
            f"-- \n"
            f"TLP:{out.classification}. Handle accordingly.\n"
            f"This message carries a summary only; the content stays in "
            f"{PRODUCT}.\n"
        )
    message["From"] = os.environ.get("SMTP_FROM", f"{PRODUCT.lower()}@localhost")
    message["To"] = out.address or ""
    # Mail clients honour these; it costs nothing and it stops a summary
    # ending up in a Slack unfurl or an AI inbox assistant's index.
    message["Auto-Submitted"] = "auto-generated"
    message["X-Auto-Response-Suppress"] = "All"
    message.set_content(text)
    return message


def webhook_payload(out: Outgoing, *, redacted: bool) -> dict:
    """The JSON a webhook receives. Same split as email: the redacted form
    says a thing happened and nothing about what."""
    if redacted:
        return {
            "event": "notification",
            "notification_id": str(out.notification_id),
            "redacted": True,
            "detail": "content classified above the destination ceiling",
        }
    return {
        "event": "notification",
        "notification_id": str(out.notification_id),
        "kind": out.kind,
        "priority": out.priority,
        "subject": out.subject,
        "summary": out.summary,
        "tlp": out.classification,
        "case_code": out.case_code,
        "redacted": False,
    }


def sign(payload: bytes, secret: str) -> str:
    """HMAC-SHA256 over the exact bytes sent, hex, prefixed with the scheme
    so the algorithm can be rotated without the receiver guessing. This is
    signature v1 and it is unchanged: no time is in the signed string."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), payload,
                                hashlib.sha256).hexdigest()


def sign_v2(payload: bytes, secret: str, timestamp: int) -> str:
    """The value of the `X-NocTORnal-Signature-V2` header: `t=<unix seconds>,v2=<hex>`.

    `<hex>` is the lowercase hex HMAC-SHA256, keyed with the secret's UTF-8 bytes, over the ASCII
    decimal timestamp, one full stop and the exact body bytes. The timestamp is the time of this
    attempt, so a retry is signed again and a receiver's window judges how fresh the post is. The
    body begins with a brace, so a v1 signature can never be read as a v2 one.
    """
    stamp = str(int(timestamp))
    mac = hmac.new(secret.encode("utf-8"), stamp.encode("ascii") + b"." + payload,
                   hashlib.sha256).hexdigest()
    return f"t={stamp},v2={mac}"


def webhook_signature_version(env=None) -> tuple[str | None, str | None]:
    """(version, None) for the webhook destination's signature setting, or (None, the sentence)
    for a value that is neither v1 nor v2.

    Unset is v1. An invalid value is a refusal, never a fall back to v1: a misspelt v2 that quietly
    sent v1 would drop the timestamp its operator asked for.
    """
    env = os.environ if env is None else env
    value = (env.get(WEBHOOK_SIGNATURE_ENV) or "").strip().lower()
    if value in ("", SIGNATURE_V1):
        return SIGNATURE_V1, None
    if value == SIGNATURE_V2:
        return SIGNATURE_V2, None
    return None, (f"{WEBHOOK_SIGNATURE_ENV} is not v1 or v2, so it is not known "
                  f"which signature the webhook should carry.")


def webhook_signature_problem(env=None) -> str | None:
    """The sentence for a webhook signature setting that cannot be used, or
    None. v2 with no secret is one: there is nothing to sign with, and a
    timestamp that nothing signs proves nothing, so the delivery is held
    rather than sent looking signed."""
    env = os.environ if env is None else env
    version, problem = webhook_signature_version(env)
    if problem:
        return problem
    if version == SIGNATURE_V2 and not env.get(WEBHOOK_SECRET_ENV):
        return (f"{WEBHOOK_SIGNATURE_ENV} is v2 and {WEBHOOK_SECRET_ENV} is not set, "
                f"so there is nothing to sign with, and a timestamp that nothing "
                f"signs proves nothing.")
    return None


# Where a webhook went, withheld.

_ENDPOINT = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(.*)", re.DOTALL)
_WITHHELD_PATH = re.compile(r"(/[^?#]+|/?\?)", re.DOTALL)


def _fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


def redact_endpoint(url: str) -> str:
    """The webhook address as the ledger stores it.

    Keeps the scheme and the authority as written, drops any userinfo, and replaces a path or query
    with a fingerprint, because incoming-webhook URLs carry their bearer secret in the path. Text
    that does not parse becomes "[endpoint withheld: <8 hex>]".

    Works on the raw text (no lower-casing, IPv6 brackets kept, a bare "?" withholds) so migration
    0096's SQL twin matches it exactly; a parity test holds the two together. Idempotent.
    """
    if re.fullmatch(r".*/\[path withheld: [0-9a-f]{8}\]", url, re.DOTALL) or \
            re.fullmatch(r"\[endpoint withheld: [0-9a-f]{8}\]", url):
        return url
    match = _ENDPOINT.fullmatch(url)
    if match is None:
        return f"[endpoint withheld: {_fingerprint(url)}]"
    scheme, authority, rest = match.groups()
    authority = authority.rsplit("@", 1)[-1]
    shown = f"{scheme}://{authority}"
    if _WITHHELD_PATH.match(rest):
        shown += f"/[path withheld: {_fingerprint(url)}]"
    return shown


# Routes (docs/00 decision 68, docs/20 section 9)

def smtp_endpoint() -> tuple[str | None, int | None, str | None]:
    """(host, port, problem). The problem is a sentence, never a value."""
    host = os.environ.get("SMTP_HOST", "").strip()
    if not host:
        return None, None, "SMTP_HOST is not set, so there is no relay to send email to."
    try:
        port = int(os.environ.get("SMTP_PORT", "587").strip() or "587")
    except ValueError:
        return host, None, "SMTP_PORT is not a port number."
    if not 1 <= port <= 65535:
        return host, None, "SMTP_PORT is not a port number."
    return host, port, None


def webhook_url() -> str | None:
    value = os.environ.get("NOCTORNAL_WEBHOOK_URL", "").strip()
    return value or None


def _webhook_http_allowed() -> bool:
    return (not production() and os.environ.get(WEBHOOK_ALLOW_HTTP_ENV, "")
            .strip().lower() in {"1", "true", "yes", "on"})


def configured_integrations(env=None) -> list[str]:
    """The notify integrations this environment configures, by route name:
    `smtp` when SMTP_HOST is set and `webhook` when NOCTORNAL_WEBHOOK_URL
    is. One reading of "configured", so a caller and the transports cannot
    disagree about it."""
    env = os.environ if env is None else env
    names = []
    if env.get("SMTP_HOST", "").strip():
        names.append(ROUTE_SMTP)
    if env.get("NOCTORNAL_WEBHOOK_URL", "").strip():
        names.append(ROUTE_WEBHOOK)
    return names


@dataclass(frozen=True)
class RouteState:
    """How a channel leaves: its route's name, whether it is usable,
    whether it is proxied, and why not when it is not."""

    name: str
    ok: bool
    proxied: bool
    why: str | None
    route: object | None = field(default=None, compare=False, repr=False)

    def as_dict(self) -> dict:
        return {"name": self.name, "ok": self.ok, "proxied": self.proxied,
                "why": self.why}


def _default_route_for():
    from noctornal_api import egress
    return egress.route_for


def _not_allowed(name: str, host: str, port: int) -> str:
    shown = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return (f"The egress route {name} does not allow {shown}. An administrator "
            f"adds it in Administration, Egress.")


def route_state(channel: str, conn, *, route_for: Callable | None = None) -> RouteState:
    """The one reader of "can this channel leave, and how" for the drain, readiness, the overview
    and the preferences."""
    from noctornal_api.egress import RouteUnavailable

    route_for = route_for or _default_route_for()
    if channel == SMTP:
        name = ROUTE_SMTP
        host, port, problem = smtp_endpoint()
        if problem:
            return RouteState(name, False, False, problem)
        try:
            declared = (Rule.for_host(host, {port}),)
        except ValueError:
            return RouteState(name, False, False,
                              "SMTP_HOST is not a host name or an address.")
    elif channel == WEBHOOK:
        name = ROUTE_WEBHOOK
        url = webhook_url()
        if url is None:
            return RouteState(name, False, False,
                              "NOCTORNAL_WEBHOOK_URL is not set, so there is "
                              "nowhere to post.")
        try:
            target = split_url(url)
        except Refusal as refusal:
            return RouteState(name, False, False,
                              f"NOCTORNAL_WEBHOOK_URL cannot be used: {refusal}.")
        if target.scheme != "https" and not _webhook_http_allowed():
            return RouteState(name, False, False,
                              "NOCTORNAL_WEBHOOK_URL is not https, and a webhook "
                              "carries case summaries.")
        # A signature setting that cannot be used HOLDS the channel, as a missing route does.
        signature_problem = webhook_signature_problem()
        if signature_problem:
            return RouteState(name, False, False, signature_problem)
        host, port = target.host, target.port
        try:
            declared = (Rule.for_url(url),)
        except (Refusal, ValueError):
            return RouteState(name, False, False,
                              "NOCTORNAL_WEBHOOK_URL names no usable host.")
    else:
        raise ValueError(f"route_state has no route for channel {channel!r}")
    try:
        route = route_for("integration", name, conn=conn, declared=declared)
    except RouteUnavailable as exc:
        return RouteState(name, False, False, str(exc))
    if not route.permits(host, port):
        return RouteState(name, False, bool(route.proxied),
                          _not_allowed(name, host, port))
    return RouteState(name, True, bool(route.proxied), None, route)


def route_problem(channel: str, conn, *, route_for: Callable | None = None) -> str | None:
    """None when the channel's route exists and permits its endpoint;
    otherwise the sentence saying why it is held."""
    state = route_state(channel, conn, route_for=route_for)
    return None if state.ok else state.why


def route_line(state: RouteState) -> str:
    """The route in words, for readiness evidence and the overview."""
    if not state.ok:
        return f"Held: {state.why}"
    if state.proxied:
        return f"through egress route {state.name}, proxied"
    return (f"through egress route {state.name}, direct (development: the "
            f"network boundary is not in force)")


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------

class _RoutedSMTP(smtplib.SMTP):
    """smtplib, dialling through the route: `_get_socket` is the one place
    smtplib opens a socket, and it now returns the pinned connection (or
    the proxy's CONNECT tunnel), watched by the session's Deadline."""

    def __init__(self, *, route, deadline, host: str, port: int, timeout: float):
        self._route = route
        self._deadline = deadline
        super().__init__(host, port, timeout=timeout)

    def _get_socket(self, host, port, timeout):
        return pinned_http.open_connection(self._route, host, port,
                                           timeout=timeout, deadline=self._deadline)

    def starttls(self, *args, **kwargs):
        # STARTTLS replaces the socket, so the watchdog watches the new one (docs/20 section 5.7).
        result = super().starttls(*args, **kwargs)
        self._deadline.watch(self.sock)
        return result


class _RoutedSMTP_SSL(smtplib.SMTP_SSL):
    """Implicit TLS on 465: open_connection wraps the socket with the
    certificate checked against the relay's name, under the watchdog."""

    def __init__(self, *, route, deadline, host: str, port: int,
                 timeout: float, context: ssl.SSLContext):
        self._route = route
        self._deadline = deadline
        super().__init__(host, port, timeout=timeout, context=context)

    def _get_socket(self, host, port, timeout):
        return pinned_http.open_connection(self._route, host, port,
                                           timeout=timeout, deadline=self._deadline,
                                           tls=self.context)


def send_smtp(message: EmailMessage, *, route) -> None:
    """Explicit TLS on 587 or implicit on 465 (docs/07: "never plaintext"), except for an
    explicitly declared development relay.

    The exception has its own environment variable rather than "TLS failed, carry on": a transport
    that silently downgrades sends case summaries in the clear on the day the certificate expires.
    In production it never applies, whatever the variable says (the cron does not run
    verify_environment). The relay socket comes from `pinned_http.open_connection` through `route`,
    and one Deadline of SMTP_SEND_SECONDS bounds the whole session.
    """
    host, port, problem = smtp_endpoint()
    if problem:
        raise TransportError(problem)
    user = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    plaintext_ok = (not production() and os.environ.get(
        "SMTP_ALLOW_PLAINTEXT", "").lower() in {"1", "true"})
    context = ssl.create_default_context()
    try:
        with pinned_http.secret_in_scope(*(v for v in (password,) if v)), \
                pinned_http.Deadline(SMTP_SEND_SECONDS) as deadline:
            if port == 465:
                client = _RoutedSMTP_SSL(route=route, deadline=deadline, host=host,
                                         port=port, timeout=10, context=context)
            else:
                client = _RoutedSMTP(route=route, deadline=deadline, host=host,
                                     port=port, timeout=10)
            try:
                if port != 465:
                    try:
                        client.starttls(context=context)
                    except (smtplib.SMTPException, ssl.SSLError):
                        if not plaintext_ok:
                            raise TransportError(
                                "the SMTP server would not negotiate STARTTLS and "
                                "SMTP_ALLOW_PLAINTEXT is not set; refusing to send "
                                "a case summary in the clear") from None
                        log.warning("sending over plaintext SMTP: development only")
                if user and password:
                    client.login(user, password)
                client.send_message(message)
            finally:
                try:
                    client.quit()
                except Exception:  # noqa: BLE001 - the mail is already sent or not
                    pass
    except TransportError:
        raise
    # These run after `secret_in_scope` has ended, so the password is named to `redact` again: a
    # relay that echoes it (an AUTH reply quoting the base64 of the credential) would otherwise
    # reach the delivery ledger and the log.
    except pinned_http.OutboundError as exc:
        raise TransportError("SMTP relay unreachable: " + pinned_http.redact(
            str(exc), secrets=tuple(v for v in (password,) if v))) from None
    except (smtplib.SMTPException, OSError) as exc:
        raise TransportError("SMTP send failed: " + pinned_http.redact(
            str(exc), secrets=tuple(v for v in (password,) if v))) from None


def send_webhook(url: str, payload: dict, secret: str | None, *, route,
                 clock: Callable[[], float] | None = None) -> None:
    """POST the payload through `route`. No redirect is followed and no environment proxy is read.
    http:// is refused unless the development flag is set, and in production always.

    The signature is v1 unless the destination opted into v2 with NOCTORNAL_WEBHOOK_SIGNATURE. A v2
    delivery carries only the v2 header, never the v1 one beside it: a v1 signature covers the body
    alone, so a delivery with both could be replayed by cutting off the v2 header and keeping v1.
    `clock` is the time source in seconds since the epoch, injectable so a test fixes the timestamp.
    """
    try:
        target = split_url(url)
    except Refusal as refusal:
        raise TransportError(f"the webhook address cannot be used: {refusal}") from None
    if target.scheme != "https" and not _webhook_http_allowed():
        raise TransportError(
            "the webhook address is not https, and a webhook carries case "
            "summaries; refusing to post them in the clear")
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    headers = {"Content-Type": "application/json"}
    version, problem = webhook_signature_version()
    if problem:
        raise TransportError(problem)
    if version == SIGNATURE_V2 and not secret:
        raise TransportError(
            f"{WEBHOOK_SIGNATURE_ENV} is v2 and there is no webhook secret, so "
            f"nothing was signed and nothing was sent")
    if secret:
        if version == SIGNATURE_V2:
            headers[SIGNATURE_HEADER_V2] = sign_v2(
                body, secret, int((clock or time.time)()))
        else:
            headers[SIGNATURE_HEADER] = sign(body, secret)
    try:
        pinned_http.fetch_response(
            url, route=route, method="POST", headers=headers, body=body,
            max_redirects=0, user_agent=WEBHOOK_USER_AGENT,
            deadline=WEBHOOK_SECONDS, max_bytes=WEBHOOK_MAX_BYTES,
            secrets=tuple(v for v in (secret,) if v))
    except pinned_http.HttpStatusError as exc:
        if 300 <= exc.status < 400:
            where = exc.location_host or "another address"
            raise TransportError(
                f"the webhook answered with a redirect to {where}; redirects "
                f"are not followed") from None
        raise TransportError(
            f"webhook returned {exc.status}", retry_after=exc.retry_after,
            cause=RATE_LIMITED if exc.status == 429 else TRANSPORT_ERROR) from None
    except pinned_http.OutboundError as exc:
        raise TransportError("webhook unreachable: "
                             + pinned_http.redact(str(exc))) from None


# ---------------------------------------------------------------------------
# The outbox drain
# ---------------------------------------------------------------------------

#: Due, and still deliverable to this recipient, on a channel that is not held.
#:
#: `deliverable_predicate` (`readable_predicate`, the centre's rule, over the element's labels as
#: they stand now) is imported from `notifications` rather than restated. A drain that disagrees
#: with the centre it drains is worse than either rule alone: between the notification being written
#: and the drain running, the recipient may lose access or clearance, and the summary must not go
#: out by email on the one path that crosses the boundary.
#:
#: `d.channel = ANY(%s)` is the channels this pass can send: JIRA is never in it (it has its own
#: capped query) and a channel whose route is missing is held, not attempted.
#:
#: The labels the gate judges are the notification's composed with its case's and its element's as
#: they stand now (`CASE_LABELS_SQL`), the way an export composes them, because the notification's
#: own were fixed when it was raised. `notifications.element_rows_sql` says which elements are read.
#: The recipient must dominate all of them.
CASE_LABELS_SQL = f"""greatest(n.classification, coalesce(c.classification, n.classification),
                (SELECT max(f.classification) FROM ({element_rows_sql('n')}) f)),
       n.compartments || coalesce(c.compartments, '{{}}'::text[])
         || coalesce((SELECT array_agg(DISTINCT k)
                        FROM ({element_rows_sql('n')}) f, unnest(f.compartments) AS k),
                     '{{}}'::text[])"""

_DUE_SQL = f"""
SELECT d.id, d.notification_id, d.channel, d.attempts,
       n.recipient_id, n.case_id, n.kind, n.priority, n.subject, n.summary,
       {CASE_LABELS_SQL},
       coalesce(p.address, u.email), c.code
  FROM notify.delivery d
  JOIN notify.notification n ON n.id = d.notification_id
  JOIN iam.app_user u ON u.id = n.recipient_id
  LEFT JOIN notify.preference p
         ON p.user_id = n.recipient_id AND p.channel = d.channel
  LEFT JOIN core."case" c ON c.id = n.case_id
 WHERE d.state = 'PENDING' AND d.deliver_after <= now()
   AND d.channel = ANY(%s)
   AND {deliverable_predicate('n')}
 ORDER BY n.priority ASC, d.deliver_after ASC
 LIMIT %s
"""

#: Due rows of channels held this pass: counted, never touched.
_HELD_SQL = f"""
SELECT count(*)
  FROM notify.delivery d
  JOIN notify.notification n ON n.id = d.notification_id
 WHERE d.state = 'PENDING' AND d.deliver_after <= now()
   AND d.channel = ANY(%s)
   AND {deliverable_predicate('n')}
"""

#: The other half of the same rule. A PENDING delivery whose recipient may no longer read it would
#: sit in the outbox forever if `due()` merely skipped it: an undrainable queue and (invariant 12) a
#: silent drop dressed as a pending one. So it is closed out explicitly, with a reason, before each
#: drain.
#:
#: It is SUPPRESSED rather than REFUSED, with `redacted` left false: REFUSED with `redacted = true`
#: means the gate refused the content and a stub went out, and here nothing went out. `attempts` is
#: not incremented because nothing was attempted.
_REVOKE_SQL = f"""
UPDATE notify.delivery d
   SET state = 'SUPPRESSED', last_attempt_at = now(), cause = 'REVOKED',
       detail = 'the recipient may no longer read this notification: '
                'clearance, compartments or case assignment changed after '
                'it was queued'
  FROM notify.notification n
 WHERE n.id = d.notification_id
   AND d.state = 'PENDING'
   AND NOT ({deliverable_predicate('n')})
RETURNING d.id
"""


def due(conn: psycopg.Connection, limit: int = MAX_PER_DRAIN, *,
        channels: tuple[str, ...] = (SMTP, WEBHOOK)) -> list[Outgoing]:
    rows = conn.execute(_DUE_SQL, (list(channels), limit)).fetchall()
    return [Outgoing(
        delivery_id=r[0], notification_id=r[1], channel=r[2], attempts=r[3],
        recipient_id=r[4], case_id=r[5], kind=r[6], priority=r[7],
        subject=r[8], summary=r[9], classification=r[10],
        compartments=frozenset(r[11] or []), address=r[12], case_code=r[13],
    ) for r in rows]


def count_held(conn: psycopg.Connection, channels: list[str]) -> int:
    if not channels:
        return 0
    return int(conn.execute(_HELD_SQL, (channels,)).fetchone()[0])


def revoke_undeliverable(conn: psycopg.Connection) -> int:
    """Close out every PENDING delivery the recipient may no longer read.

    Not time-bounded and not limited: it is a cheap UPDATE over a small working set, and a cap would
    delay a revocation by several drains. Returns how many were closed.
    """
    return len(conn.execute(_REVOKE_SQL).fetchall())


def destination_for(channel: str) -> Destination:
    return {SMTP: Destination.SMTP, WEBHOOK: Destination.WEBHOOK,
            JIRA: Destination.JIRA}[channel]


def configured_ceiling(channel: str) -> str | None:
    """The ceiling the deployment set for the SMTP or webhook channel (`NOCTORNAL_SMTP_CEILING`,
    `NOCTORNAL_WEBHOOK_CEILING`), or None when it set none.

    The drain and a report's release both judge against it; one reader keeps the two from differing.
    """
    return os.environ.get(f"NOCTORNAL_{channel}_CEILING") or None


def dispatch_due(conn: psycopg.Connection, *, limit: int = MAX_PER_DRAIN,
                 send_mail=send_smtp, post_webhook=send_webhook,
                 route_for: Callable | None = None, jira_client=None) -> dict:
    """Drain the outbox once.

    A function you call, not a loop: there is no worker process in this build (decision 30), so an
    operator, a cron entry or a test drives it. The transports are injectable so tests exercise the
    gate, the redaction and the ledger without a mail server. An injected transport stands in for
    the route as well as the relay; only the default transports are held behind their route.

    One pass, in this order: revoke (`revoke_undeliverable`, before the drain rather than as a
    filter inside it, or rows would queue up invisibly); withdraw the Jira rows nothing may route
    any more (`jira.withdraw_unroutable`); the email and webhook loop; Jira's own pass
    (`jira.JiraPass`, capped per pass and by wall clock, so email is never behind Jira); then the
    producers. A channel whose route is missing or does not allow its endpoint is HELD: its due
    rows are counted into `held` and left alone.

    The producers run after the drain loop, so a drain sends what was already due when it started
    and what the producers raise goes out on the next pass. Otherwise an URGENT escalation, which
    `deliver_after` makes due now, would send mail from a drain whose only queued row was DEFERRED.

    One drain at a time: both producers dedupe by reading the rows they are about to write, and
    `notify.notification` has no unique index, so two overlapping drains would each write one.
    `pg_try_advisory_lock` rather than `pg_advisory_lock`, so an operator who dispatches while cron
    holds the lock gets an immediate all-zero drain. The lock also serialises Jira's pass, which
    claims a per-event posting row.

    Every key in the `counters` literal is a field of the HTTP `DrainOut` model, and
    test_ui_invariants reads the literal to hold the model to it, so a new counter goes in the
    literal, not on a later line. The producers assign into it after the loop.
    """
    counters = {"sent": 0, "redacted": 0, "refused": 0, "failed": 0,
                "revoked": 0, "held": 0, "deferred": 0, "withdrawn": 0,
                "reviews_due": 0, "escalated": 0}
    locked = conn.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                          (_DRAIN_LOCK,)).fetchone()[0]
    if not locked:
        # Not an error and not a failure: another drain is doing exactly
        # this work right now. All-zero is the honest report -- this call
        # sent nothing, revoked nothing and produced nothing.
        log.info("a drain is already running; this one did nothing")
        return counters
    try:
        from noctornal_api import jira

        counters["revoked"] = revoke_undeliverable(conn)
        counters["withdrawn"] = jira.withdraw_unroutable(conn)

        # Which channels this pass can send, and the route each takes.
        routes: dict[str, object] = {}
        sendable: list[str] = []
        held_channels: list[str] = []
        for channel, injected in ((SMTP, send_mail is not send_smtp),
                                  (WEBHOOK, post_webhook is not send_webhook)):
            if injected:
                sendable.append(channel)
                continue
            state = route_state(channel, conn, route_for=route_for)
            if state.ok:
                sendable.append(channel)
                routes[channel] = state.route
            else:
                held_channels.append(channel)
        counters["held"] = count_held(conn, held_channels)

        for out in (due(conn, limit, channels=tuple(sendable)) if sendable else []):
            decision = can_egress(
                out.classification, destination_for(out.channel),
                compartments=out.compartments,
                destination_ceiling=configured_ceiling(out.channel),
            )
            redacted = decision.denied
            route = routes.get(out.channel)
            if route is not None and hasattr(route, "tagged"):
                route = route.tagged(f"delivery:{out.delivery_id}")
            try:
                if out.channel == SMTP:
                    if not out.address:
                        raise TransportError("no email address for this recipient")
                    # A list stored before the single-address rule is undeliverable, never
                    # expanded into one RCPT per address by smtplib.
                    if single_address_domain(out.address) is None:
                        raise TransportError(
                            "the delivery address is not one plain address, "
                            "so nothing was sent to it")
                    message = render_email(out, redacted=redacted)
                    if route is None:
                        send_mail(message)
                    else:
                        send_mail(message, route=route)
                    sent_to = out.address
                elif out.channel == WEBHOOK:
                    url = webhook_url()
                    if not url:
                        raise TransportError("NOCTORNAL_WEBHOOK_URL is not set")
                    payload = webhook_payload(out, redacted=redacted)
                    secret = os.environ.get("NOCTORNAL_WEBHOOK_SECRET")
                    if route is None:
                        post_webhook(url, payload, secret)
                    else:
                        post_webhook(url, payload, secret, route=route)
                    sent_to = redact_endpoint(url)
                else:
                    raise TransportError(f"no transport for channel {out.channel}")
            except TransportError as exc:
                _fail(conn, out, str(exc), cause=exc.cause,
                      retry_after=exc.retry_after)
                counters["failed"] += 1
                continue
            except Exception as exc:  # noqa: BLE001 - every failure is a ledger row
                _fail(conn, out, pinned_http.redact(str(exc)))
                counters["failed"] += 1
                continue

            if redacted:
                _succeed(conn, out, state=REFUSED, redacted=True,
                         detail=decision.reason, sent_to=sent_to,
                         exposure="STUB", cause=EGRESS_REFUSED)
                counters["redacted"] += 1
                counters["refused"] += 1
            else:
                _succeed(conn, out, state=SENT, redacted=False, detail=None,
                         sent_to=sent_to, exposure="SUMMARY")
                counters["sent"] += 1

        try:
            jira_counts = jira.JiraPass(conn, client_factory=jira_client,
                                        route_for=route_for).run()
        except Exception:  # noqa: BLE001 - Jira never silences the producers
            # A Jira pass that fails outside any one row (a destination read, the credential, a
            # bug) must not take the review and URGENT escalation notices with it. The failure is
            # logged and counted.
            log.exception("the Jira pass failed; the producers still run")
            jira_counts = {"failed": 1}
        for key in ("sent", "refused", "failed", "held", "deferred"):
            counters[key] += jira_counts.get(key, 0)

        # After the loop, on purpose. See "The producers run AFTER the drain
        # loop" above: what these raise is due next pass, not this one.
        counters["reviews_due"] = case_reviews_due(conn)
        counters["escalated"] = escalate_unacknowledged(conn)
    finally:
        # A session lock outlives the statement that took it, so an
        # exception escaping the drain would otherwise strand it for the
        # life of the connection -- and in a pooled process, for the life of
        # the pool.
        conn.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0))",
                     (_DRAIN_LOCK,))
    return counters


def _succeed(conn: psycopg.Connection, out: Outgoing, *, state: str,
             redacted: bool, detail: str | None, sent_to: str | None,
             exposure: str | None, cause: str | None = None,
             jira_link_id: UUID | None = None, attempted: bool = True) -> None:
    """Record the outcome.

    A stub that went out is REFUSED, not SENT: what the gate refused was the content, and an auditor
    asking "did the summary leave the boundary" must get a straight no.
    `delivery_sent_has_timestamp` ties SENT to `sent_at`, so a REFUSED row carries only
    `last_attempt_at`.

    `sent_to` is where it went, resolved at drain time (migration 0044): the address for email, the
    withheld endpoint for a webhook (0096), the browse URL for Jira. `exposure` is what left (0095).
    `attempted` is false for a row that consumed no attempt (Jira's gate refusal sends nothing;
    ALREADY_ON_ISSUE rides another recipient's post).
    """
    conn.execute(
        """UPDATE notify.delivery
              SET state = %s, sent_at = %s,
                  attempts = attempts + %s,
                  last_attempt_at = now(), redacted = %s, detail = %s,
                  sent_to = %s, exposure = %s, cause = %s,
                  jira_link_id = coalesce(%s, jira_link_id)
            WHERE id = %s""",
        (state, datetime.now(timezone.utc) if state == SENT else None,
         1 if attempted else 0, redacted, detail, sent_to, exposure, cause,
         jira_link_id, out.delivery_id))


#: Retry-After is honoured within these bounds.
RETRY_AFTER_FLOOR_S = 60
RETRY_AFTER_CAP_S = 3600


def _fail(conn: psycopg.Connection, out: Outgoing, error: str, *,
          cause: str = TRANSPORT_ERROR, retry_after: float | None = None) -> None:
    """A failure is a row, never a shrug (invariant 12).

    Retries back off by attempt count and then STOP. A delivery retried
    forever is an outbox that never drains and a log nobody reads. A far
    end's Retry-After, clamped to a minute and an hour, is honoured when it
    asks for longer than the back-off would wait.
    """
    attempts = out.attempts + 1
    if attempts >= MAX_ATTEMPTS:
        conn.execute(
            """UPDATE notify.delivery
                  SET state = 'FAILED', attempts = %s, last_attempt_at = now(),
                      detail = %s, cause = 'GAVE_UP'
                WHERE id = %s""",
            (attempts, f"gave up after {attempts} attempts: {error}"[:500],
             out.delivery_id))
        log.error("delivery %s to %s gave up: %s", out.delivery_id,
                  out.channel, error)
        return
    wait_s = float(60 * 2 ** attempts)
    if retry_after is not None:
        wait_s = max(wait_s, min(max(float(retry_after), RETRY_AFTER_FLOOR_S),
                                 RETRY_AFTER_CAP_S))
    conn.execute(
        """UPDATE notify.delivery
              SET attempts = %s, last_attempt_at = now(), detail = %s,
                  cause = %s,
                  deliver_after = now() + (interval '1 second' * %s)
            WHERE id = %s""",
        (attempts, error[:500], cause if cause in CAUSES else TRANSPORT_ERROR,
         wait_s, out.delivery_id))
