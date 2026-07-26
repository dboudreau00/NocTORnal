"""Outbound transports: SMTP and HMAC-signed webhooks, and the outbox drain
that feeds them.

Every function here calls `egress.can_egress()` before it sends anything.
That is invariant 8, and this file is the reason it exists -- docs/07:

    Integrations are the leak path in every system of this kind. Not
    because anyone intends it, but because a Jira ticket auto-created from
    a watch hit quietly copies intelligence into a system with a completely
    different access model and a much wider audience.

## The content rules, enforced structurally

docs/07 is specific about email, and it is specific because email is the
worst channel available: it sits in inboxes, gets forwarded, and syncs to
phones that render the subject line on a lock screen.

    Subject line carries no intelligence. Body carries a summary and a deep
    link, not the content.

`render_email()` is the only function that builds an email, and it reads
`subject` and `summary` from the notification. **It never touches `body`.**
That is asserted by a test that patches the column out and checks the mail
still renders -- a comment saying "do not use body here" would survive
exactly one refactor.

## What happens to content that cannot leave

Not a silent drop, and not a downgrade. The delivery row is written
`REFUSED` with the gate's reason code, and -- when the recipient would
otherwise have been left with nothing -- a **stub** goes out instead: the
fact that something is waiting, with no case content and no case code.
The full notification is still in the centre, behind the access gate, which
is where it should have been read anyway.

This is the honest reading of docs/07's "Optional: refuse to send anything
above AMBER, notify in-app only": the *content* stays in, the *fact* that
there is something to look at may go out, and the delivery ledger records
which of the two happened.

## Deep links carry no token

docs/07 floats "single-use, short-TTL deep links". They are not built, and
the link is a plain URL that lands on the login page. A single-use token in
an email is a bearer credential in the least trustworthy channel in the
system; requiring the recipient to authenticate is both simpler and
stronger. If deep links are wanted later they must be scoped to navigation
only and never to access.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from uuid import UUID

import psycopg

from noctornal_api.egress import Destination, can_egress
from noctornal_api.notifications import (
    JIRA,
    REFUSED,
    SENT,
    SMTP,
    WEBHOOK,
    readable_predicate,
)

log = logging.getLogger("noctornal.transports")

# A runaway loop must not fire ten thousand emails (docs/07). Applied per
# drain rather than per hour: the drain is the only thing that sends, so
# bounding it bounds the blast radius of any producer.
MAX_PER_DRAIN = 200
# After this many failures a delivery stops being retried and stays FAILED.
# A permanently-retried delivery is a permanently-hot outbox.
MAX_ATTEMPTS = 5

PRODUCT = "NocTORnal"


class TransportError(Exception):
    pass


@dataclass(frozen=True)
class Outgoing:
    """One due delivery, joined to the notification it belongs to."""

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


def base_url() -> str:
    """Where a link in an email points. No default with a real hostname in
    it: a wrong link in an email is a support ticket, and a link to somebody
    else's deployment is worse."""
    return os.environ.get("NOCTORNAL_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


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
    so the algorithm can be rotated without the receiver guessing."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), payload,
                                hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------

def send_smtp(message: EmailMessage) -> None:
    """Explicit TLS on 587 or implicit on 465 (docs/07: "never plaintext"),
    with one exception: an explicitly-declared development relay.

    The exception is guarded by its own environment variable rather than by
    "TLS failed, carry on". A transport that silently downgrades is a
    transport that sends case summaries in the clear on the day the
    certificate expires.
    """
    host = os.environ.get("SMTP_HOST")
    if not host:
        raise TransportError("SMTP_HOST is not set")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    plaintext_ok = os.environ.get("SMTP_ALLOW_PLAINTEXT", "").lower() in {"1", "true"}

    if port == 465:
        client = smtplib.SMTP_SSL(host, port, timeout=10,
                                  context=ssl.create_default_context())
    else:
        client = smtplib.SMTP(host, port, timeout=10)
    try:
        if port != 465:
            try:
                client.starttls(context=ssl.create_default_context())
            except (smtplib.SMTPException, ssl.SSLError):
                if not plaintext_ok:
                    raise TransportError(
                        "the SMTP server would not negotiate STARTTLS and "
                        "SMTP_ALLOW_PLAINTEXT is not set; refusing to send a "
                        "case summary in the clear") from None
                log.warning("sending over plaintext SMTP: development only")
        if user and password:
            client.login(user, password)
        client.send_message(message)
    finally:
        try:
            client.quit()
        except Exception:  # noqa: BLE001 - the mail is already sent or not
            pass


def send_webhook(url: str, payload: dict, secret: str | None) -> None:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    headers = {"Content-Type": "application/json",
               "User-Agent": f"{PRODUCT}-webhook/1"}
    if secret:
        headers["X-NocTORnal-Signature"] = sign(body, secret)
    request = urllib.request.Request(url, data=body, headers=headers,
                                     method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status >= 400:
                raise TransportError(f"webhook returned {response.status}")
    except urllib.error.HTTPError as exc:
        raise TransportError(f"webhook returned {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise TransportError(f"webhook unreachable: {exc}") from exc


# ---------------------------------------------------------------------------
# The outbox drain
# ---------------------------------------------------------------------------

#: Due, AND still deliverable to this recipient.
#:
#: `readable_predicate` is imported from `notifications` rather than
#: restated. This query used to check only `u.is_active`, so between the
#: notification being written and the drain running the recipient could be
#: taken off the case or have their clearance lowered and the summary went
#: out by email anyway — on the one path in the system that actually crosses
#: the boundary. The notification centre would have hidden the same row.
#:
#: A drain that disagrees with the centre it drains is worse than either
#: rule alone, because the in-app copy is the thing an auditor looks at.
_DUE_SQL = f"""
SELECT d.id, d.notification_id, d.channel, d.attempts,
       n.recipient_id, n.case_id, n.kind, n.priority, n.subject, n.summary,
       n.classification, n.compartments,
       coalesce(p.address, u.email), c.code
  FROM notify.delivery d
  JOIN notify.notification n ON n.id = d.notification_id
  JOIN iam.app_user u ON u.id = n.recipient_id
  LEFT JOIN notify.preference p
         ON p.user_id = n.recipient_id AND p.channel = d.channel
  LEFT JOIN core."case" c ON c.id = n.case_id
 WHERE d.state = 'PENDING' AND d.deliver_after <= now()
   AND {readable_predicate('n')}
 ORDER BY n.priority ASC, d.deliver_after ASC
 LIMIT %s
"""

#: The other half of the same rule, and the reason it is not simply a
#: filter. A PENDING delivery whose recipient may no longer read it would
#: sit in the outbox forever if `due()` merely skipped it — a permanently
#: undrainable queue, and (invariant 12) a silent drop dressed as a pending
#: one. So it is closed out explicitly, with a reason, before each drain.
#:
#: SUPPRESSED rather than REFUSED, and `redacted` left false, because both
#: of those columns mean something specific here: REFUSED with
#: `redacted = true` is "the gate refused the content and a content-free
#: stub went out instead". Nothing went out. `attempts` is not incremented
#: for the same reason — nothing was attempted.
_REVOKE_SQL = f"""
UPDATE notify.delivery d
   SET state = 'SUPPRESSED', last_attempt_at = now(),
       detail = 'the recipient may no longer read this notification: '
                'clearance, compartments or case assignment changed after '
                'it was queued'
  FROM notify.notification n
 WHERE n.id = d.notification_id
   AND d.state = 'PENDING'
   AND NOT ({readable_predicate('n')})
RETURNING d.id
"""


def due(conn: psycopg.Connection, limit: int = MAX_PER_DRAIN) -> list[Outgoing]:
    rows = conn.execute(_DUE_SQL, (limit,)).fetchall()
    return [Outgoing(
        delivery_id=r[0], notification_id=r[1], channel=r[2], attempts=r[3],
        recipient_id=r[4], case_id=r[5], kind=r[6], priority=r[7],
        subject=r[8], summary=r[9], classification=r[10],
        compartments=frozenset(r[11] or []), address=r[12], case_code=r[13],
    ) for r in rows]


def revoke_undeliverable(conn: psycopg.Connection) -> int:
    """Close out every PENDING delivery the recipient may no longer read.

    Not time-bounded and not limited: this is a cheap UPDATE over a small
    working set, and a cap here would mean a revocation that took several
    drains to take effect. Returns how many were closed so the caller can
    report it rather than discover it in the table.
    """
    return len(conn.execute(_REVOKE_SQL).fetchall())


def destination_for(channel: str) -> Destination:
    return {SMTP: Destination.SMTP, WEBHOOK: Destination.WEBHOOK,
            JIRA: Destination.JIRA}[channel]


def dispatch_due(conn: psycopg.Connection, *, limit: int = MAX_PER_DRAIN,
                 send_mail=send_smtp, post_webhook=send_webhook) -> dict:
    """Drain the outbox once.

    Deliberately a function you CALL rather than a loop that runs: there is
    no worker process in this build (decision 30's precedent), so the drain
    is driven by an operator, a cron entry, or a test. That is a real
    limitation and it is written down rather than hidden behind a thread
    that silently dies.

    The transports are injectable so the tests exercise the gate, the
    redaction and the ledger without a mail server.

    Begins by closing out any PENDING delivery whose recipient may no longer
    read it — see `revoke_undeliverable`. That has to happen BEFORE the
    drain rather than as a filter inside it, or the rows would queue up
    invisibly forever.
    """
    counters = {"sent": 0, "redacted": 0, "refused": 0, "failed": 0,
                "revoked": revoke_undeliverable(conn)}
    for out in due(conn, limit):
        decision = can_egress(
            out.classification, destination_for(out.channel),
            compartments=out.compartments,
            destination_ceiling=os.environ.get(
                f"NOCTORNAL_{out.channel}_CEILING") or None,
        )
        redacted = decision.denied

        try:
            if out.channel == SMTP:
                if not out.address:
                    raise TransportError("no email address for this recipient")
                send_mail(render_email(out, redacted=redacted))
            elif out.channel == WEBHOOK:
                url = os.environ.get("NOCTORNAL_WEBHOOK_URL")
                if not url:
                    raise TransportError("NOCTORNAL_WEBHOOK_URL is not set")
                post_webhook(url, webhook_payload(out, redacted=redacted),
                             os.environ.get("NOCTORNAL_WEBHOOK_SECRET"))
            else:
                raise TransportError(f"no transport for channel {out.channel}")
        except Exception as exc:  # noqa: BLE001 - every failure is a ledger row
            _fail(conn, out, str(exc))
            counters["failed"] += 1
            continue

        _succeed(conn, out, redacted=redacted,
                 detail=decision.reason if redacted else None)
        counters["redacted" if redacted else "sent"] += 1
        if redacted:
            counters["refused"] += 1
    return counters


def _succeed(conn: psycopg.Connection, out: Outgoing, *, redacted: bool,
             detail: str | None) -> None:
    """Record the outcome.

    A stub that went out is REFUSED, not SENT. What the gate refused was the
    CONTENT, and an auditor asking "did the summary leave the boundary" must
    get a straight no without reconstructing it from the classification.
    `delivery_sent_has_timestamp` ties SENT to `sent_at`, so a REFUSED row
    carries only `last_attempt_at` — which is also the honest reading: the
    delivery of the notification did not happen.
    """
    state = REFUSED if redacted else SENT
    conn.execute(
        """UPDATE notify.delivery
              SET state = %s, sent_at = %s, attempts = attempts + 1,
                  last_attempt_at = now(), redacted = %s, detail = %s,
                  sent_to = %s
            WHERE id = %s""",
        (state, None if redacted else datetime.now(timezone.utc),
         redacted, detail,
         # WHERE it went, resolved at drain time (migration 0044). The
         # preference is current state; this is history, and history is
         # what answers "what left the building". A delivery queued while
         # the preference said one thing can be sent after it says
         # another, which is exactly the case worth being able to see.
         out.address if out.channel == SMTP
         else os.environ.get("NOCTORNAL_WEBHOOK_URL"),
         out.delivery_id))


def _fail(conn: psycopg.Connection, out: Outgoing, error: str) -> None:
    """A failure is a row, never a shrug (invariant 12).

    Retries back off by attempt count and then STOP. A delivery retried
    forever is an outbox that never drains and a log nobody reads.
    """
    attempts = out.attempts + 1
    if attempts >= MAX_ATTEMPTS:
        conn.execute(
            """UPDATE notify.delivery
                  SET state = 'FAILED', attempts = %s, last_attempt_at = now(),
                      detail = %s
                WHERE id = %s""",
            (attempts, f"gave up after {attempts} attempts: {error}"[:500],
             out.delivery_id))
        log.error("delivery %s to %s gave up: %s", out.delivery_id,
                  out.channel, error)
        return
    conn.execute(
        """UPDATE notify.delivery
              SET attempts = %s, last_attempt_at = now(), detail = %s,
                  deliver_after = now() + (interval '1 minute' * %s)
            WHERE id = %s""",
        (attempts, error[:500], 2 ** attempts, out.delivery_id))
