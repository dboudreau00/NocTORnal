"""Social-engineering evidence: phishing captures, BEC email, vishing calls.

docs/19. Three subsystems, one shape — a provenance row that points at WORM
exhibits, never bytes in a column — and three rules that this module exists
to enforce rather than document:

1. **A captured page is attacker-authored code.** Invariant 10 generalised.
   DOM, HAR and `.eml` bytes are marked hostile at ingest and are
   download-only from the separate sample origin. Screenshots may render,
   and only after their type is re-derived from the magic bytes, because
   `media_type` on `core.evidence` is whatever the uploading client said.

2. **The displayed identifier is the spoofed one.** Invariant 9 generalised.
   `presented_number` never becomes a selector. `header_from` never becomes
   an identity. A DKIM domain is an identity only if DKIM *passed*.

3. **The Received chain is trustworthy inwards only.** Everything above the
   receiving organisation's own MTA is attacker-writable. `seq` is stored
   recipient-first and the boundary is marked, so no consumer has to
   remember which end to believe.

Nothing here writes to `core.node` or `core.edge`. Extraction produces
proposals (invariant 3); what this module returns are *candidates*, and the
caller routes them through the proposal machinery like every other machine
output.
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.security.access import AccessResolutionError, tlp_from_name


class DeceptionError(Exception):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Hostile bytes (invariant 10, migration 0046)
# ---------------------------------------------------------------------------

#: Media types whose bytes are attacker-authored markup or code. Kept
#: deliberately broad: over-marking costs an analyst one extra click,
#: under-marking costs a stored-XSS in an authenticated analyst session on
#: the case system. `image/svg+xml` is here because an SVG is a script
#: container that happens to draw — the one "image" type that must never
#: reach a render path.
HOSTILE_MEDIA_TYPES = frozenset({
    "text/html", "application/xhtml+xml", "image/svg+xml",
    "application/xml", "text/xml", "message/rfc822", "application/mbox",
    "text/x-mail", "application/x-har", "application/json+har",
})

#: Raster image types the screenshot path may serve inline, keyed by the
#: magic bytes that PROVE it. Typed by structure, never by the declared
#: media type — `samples.file_type_of` makes the same call for the same
#: reason, and here the stakes are higher because this is the only path in
#: the platform that hands an exhibit to the browser to interpret.
_RASTER_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"BM", "image/bmp"),
)


def is_hostile_media_type(media_type: str | None) -> bool:
    """Should bytes of this declared type be marked hostile?

    Answers on the declared type because this runs at INGEST, before
    anything has looked at the bytes, and the conservative direction is to
    believe a client that says "this is HTML". The read path does not
    believe the declared type in the other direction — see `raster_type_of`.
    """
    if not media_type:
        return False
    base = media_type.split(";", 1)[0].strip().lower()
    return base in HOSTILE_MEDIA_TYPES


def raster_type_of(data: bytes) -> str | None:
    """The image type these bytes actually are, or None.

    None means "do not serve this inline", and every caller must treat it
    that way. `media_type` on `core.evidence` comes from
    `UploadFile.content_type`, which is client-supplied: an attacker-analyst
    or a compromised upload path can label an HTML document `image/png`. A
    render path that trusted the column would execute it.

    WebP and AVIF are deliberately absent. Both are container formats whose
    decoders have a materially worse CVE history than PNG/JPEG, and neither
    is needed to look at a screenshot.
    """
    for magic, media_type in _RASTER_MAGIC:
        if data.startswith(magic):
            # RIFF-family false positive guard: "BM" is only two bytes and
            # a BMP declares its own size in the header.
            if media_type == "image/bmp" and len(data) < 14:
                return None
            return media_type
    return None


# ---------------------------------------------------------------------------
# Defanging
# ---------------------------------------------------------------------------

_SCHEME_RE = re.compile(r"^(h)(ttps?)(://)", re.I)


def defang(value: str) -> str:
    """`https://evil.com/x` -> `hxxps://evil[.]com/x`.

    Not decoration. A live URL in an analyst's browser is one mis-click
    from a drive-by AND from telling the actor, from the investigating
    organisation's IP, that they are being looked at (docs/19 §5). The UI
    also renders these non-clickable; this is the belt to that pair of
    braces, and it is applied server-side so an API consumer that is not
    the UI gets it too.
    """
    if not value:
        return value
    # `https` -> `hxxps`: keep the leading h, replace the two t's, keep
    # the rest. Slicing from [2] rather than taking [-1] is the difference
    # between `hxxps` and `hxxs` — a defanged URL that has quietly lost a
    # character is no longer the URL, which matters when an analyst copies
    # it into a report.
    out = _SCHEME_RE.sub(lambda m: m.group(1) + "xx" + m.group(2)[2:] + m.group(3), value)
    # Only the authority is bracketed. Dots in a path are not navigable and
    # bracketing them makes long URLs unreadable for no gain.
    #
    # `parts[1] == ""` is the load-bearing half of this test, and it was
    # missing. `split("/", 3)` puts the authority at index 2 ONLY when a
    # `scheme://` occupied indices 0 and 1. Without a scheme —
    # `paypal-secure.example/login` — index 2 is a PATH segment, so the
    # authority was never bracketed and, since no scheme matched either,
    # the function returned the string untouched. A live host, from a
    # helper whose whole job is that it is not one.
    #
    # That form is not exotic: `requested_url` and `final_url` are free
    # text and a victim report routinely omits the scheme, and
    # `GET /deception/defang` is documented as safe for a report.
    parts = out.split("/", 3)
    if len(parts) >= 3 and parts[1] == "" and parts[2]:
        parts[2] = parts[2].replace(".", "[.]")
        out = "/".join(parts)
    else:
        # No authority to isolate — bracket the first segment, which is
        # where a bare host lives, and leave any path alone.
        head, sep, tail = out.partition("/")
        out = head.replace(".", "[.]") + sep + tail
    return out


# ---------------------------------------------------------------------------
# The Received chain
# ---------------------------------------------------------------------------

_RECEIVED_FROM = re.compile(r"\bfrom\s+([^\s;()]+)", re.I)
_RECEIVED_BY = re.compile(r"\bby\s+([^\s;()]+)", re.I)
_RECEIVED_WITH = re.compile(r"\bwith\s+([A-Za-z0-9/]+)", re.I)
_RECEIVED_IP = re.compile(r"[\[(]\s*(?:IPv6:)?([0-9a-fA-F:.]{3,45})\s*[\])]")
_TLS_HINT = re.compile(r"\b(ESMTPS|ESMTPSA|TLS|SSL|version=TLS)\b", re.I)


@dataclass(frozen=True)
class Hop:
    """One `Received` header, numbered recipient-first.

    `seq = 0` is the hop closest to the recipient — the receiving
    organisation's own MTA — and trust decays monotonically as `seq` rises.
    """

    seq: int
    raw: str
    from_host: str | None
    from_ip: str | None
    by_host: str | None
    protocol: str | None
    tls_used: bool | None
    received_at: datetime | None
    is_trusted_boundary: bool = False
    #: True when the boundary is the seq-0 DEFAULT rather than a hop whose
    #: `by` host was actually recognised as the recipient's.
    #:
    #: The distinction is not cosmetic. An assumed boundary means nobody
    #: told this system which MTAs are ours, so hop 0 is "the first line in
    #: the file" and not "a machine we control" — and its `from_ip` is
    #: therefore an address INSIDE the victim's network, not an
    #: observation of the sender. It lives on the hop rather than being
    #: re-derived from the environment by each consumer, because a
    #: consumer that re-read `NOCTORNAL_TRUSTED_MTA_HOSTS` could disagree
    #: with the parse that produced these hops.
    boundary_is_assumed: bool = False


def trusted_mta_suffixes() -> tuple[str, ...]:
    """Host suffixes belonging to the receiving organisation.

    From `NOCTORNAL_TRUSTED_MTA_HOSTS` (comma-separated). No default and no
    secret: an unset value means "we do not know which MTAs are ours", and
    the honest consequence is that only the first hop is trusted.
    """
    raw = os.environ.get("NOCTORNAL_TRUSTED_MTA_HOSTS", "")
    return tuple(h.strip().lower().lstrip(".") for h in raw.split(",") if h.strip())


def parse_received_chain(headers: list[str],
                         trusted: tuple[str, ...] | None = None) -> list[Hop]:
    """Parse `Received:` headers into hops, RECIPIENT-FIRST.

    ## The flip, done once, here

    Each MTA *prepends* its `Received` header, so in the file the newest
    (closest to the recipient) is FIRST. That happens to be the order this
    function wants, so the incoming list is used as-is — but it is stated
    explicitly because the reverse assumption is the classic error, and it
    is the error that attributes a BEC to whatever originating IP the
    attacker typed into a forged upstream hop.

    ## Where trust stops

    Walking from `seq = 0` upward, a hop stays trusted while its `by` host
    is one of ours. The LAST such hop is the boundary. If no trusted
    suffixes are configured, the boundary is `seq = 0` — the conservative
    answer, and the only defensible one when the platform has not been told
    which MTAs belong to the recipient.

    Nothing above the boundary is evidence of anything, and the extractor
    refuses to propose infrastructure from up there.
    """
    if trusted is None:
        trusted = trusted_mta_suffixes()
    hops: list[Hop] = []
    for seq, raw in enumerate(headers):
        flat = " ".join(raw.split())
        # The date is after the last semicolon, per RFC 5321 §4.4. Split on
        # the LAST one: `for <a@b>;` comments can contain earlier ones.
        received_at = None
        if ";" in flat:
            try:
                received_at = parsedate_to_datetime(flat.rsplit(";", 1)[1].strip())
            except (ValueError, TypeError, IndexError):
                received_at = None      # invariant 12: recorded as absent
        ip_match = _RECEIVED_IP.search(flat)
        from_match = _RECEIVED_FROM.search(flat)
        by_match = _RECEIVED_BY.search(flat)
        with_match = _RECEIVED_WITH.search(flat)
        hops.append(Hop(
            seq=seq,
            raw=raw[:4000],
            from_host=from_match.group(1).lower() if from_match else None,
            from_ip=ip_match.group(1) if ip_match else None,
            by_host=by_match.group(1).lower() if by_match else None,
            protocol=with_match.group(1).upper() if with_match else None,
            tls_used=bool(_TLS_HINT.search(flat)) or None,
            received_at=received_at,
        ))
    if not hops:
        return hops

    boundary = 0
    # Assumed unless a hop's `by` host is actually recognised as ours.
    assumed = True
    if trusted:
        for hop in hops:
            host = (hop.by_host or "").lower()
            if any(host == t or host.endswith("." + t) for t in trusted):
                boundary = hop.seq
                assumed = False
            else:
                break
    return [
        Hop(**{**h.__dict__,
               "is_trusted_boundary": h.seq == boundary,
               "boundary_is_assumed": assumed})
        for h in hops
    ]


# ---------------------------------------------------------------------------
# Email forensics
# ---------------------------------------------------------------------------

_AUTH_RESULT = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
_AUTH_DOMAIN = re.compile(
    r"\b(?:header\.d|smtp\.mailfrom|header\.from|envelope-from)\s*=\s*"
    r"[<\"]?([^\s;>\",]+)", re.I)
_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'\)\]]{3,2048}", re.I)

#: Free-mail providers. A `Reply-To` at one of these on a mail claiming to
#: be from a company is the single loudest BEC signal there is — but it is
#: a SIGNAL, surfaced as a boolean for triage, never a verdict. Invariant 1
#: applies to findings as much as to attributes.
FREEMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "yahoo.co.uk", "aol.com", "protonmail.com", "proton.me",
    "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.ru", "icloud.com",
    "me.com", "tutanota.com", "tuta.io", "hushmail.com",
})

#: An `.eml` larger than this is refused rather than parsed. Header bombing
#: and deeply-nested MIME are both cheap to send and expensive to parse;
#: the cap is the same shape as `samples.MAX_SAMPLE_BYTES`.
MAX_EML_BYTES = 64 * 1024 * 1024
_MAX_HEADERS = 2000
_MAX_PARTS = 500


@dataclass
class ParsedEmail:
    """Everything the parser could establish, and what it could not.

    `gaps` is load-bearing in the same way `samples.Triage.gaps` is: a NULL
    `dkim_result` reads as "DKIM did not pass"; a recorded gap reads as
    "no Authentication-Results header was present, so nobody checked".
    Those are very different findings and invariant 12 says the difference
    must survive.
    """

    message_id: str | None = None
    header_from: str | None = None
    header_from_display: str | None = None
    header_reply_to: str | None = None
    header_return_path: str | None = None
    header_to: list[str] = field(default_factory=list)
    header_cc: list[str] = field(default_factory=list)
    subject: str | None = None
    date_header: datetime | None = None
    in_reply_to: str | None = None
    spf_result: str | None = None
    spf_domain: str | None = None
    dkim_result: str | None = None
    dkim_domain: str | None = None
    dmarc_result: str | None = None
    dmarc_domain: str | None = None
    auth_results_raw: str | None = None
    body_text: str | None = None
    has_html_body: bool = False
    extracted_urls: list[str] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    attachments: list[dict] = field(default_factory=list)
    gaps: list[dict] = field(default_factory=list)

    # -- derived findings, computed once and stored ----------------------
    @property
    def from_domain(self) -> str | None:
        return _domain_of(self.header_from)

    @property
    def from_replyto_divergent(self) -> bool:
        """Does a reply go somewhere other than where the mail claims to be
        from? Compared on the DOMAIN, not the full address: BEC routinely
        uses `ceo@company.com` -> `ceo.company@gmail.com`, and an
        address-equality test would call that convergent."""
        reply = _domain_of(self.header_reply_to)
        return bool(reply and self.from_domain and reply != self.from_domain)

    @property
    def from_returnpath_divergent(self) -> bool:
        rp = _domain_of(self.header_return_path)
        return bool(rp and self.from_domain and rp != self.from_domain)

    @property
    def reply_to_is_freemail(self) -> bool:
        return (_domain_of(self.header_reply_to) or "") in FREEMAIL_DOMAINS


def _domain_of(addr: str | None) -> str | None:
    if not addr or "@" not in addr:
        return None
    return addr.rsplit("@", 1)[1].strip().strip(">").lower() or None


def _header_str(msg: EmailMessage, name: str) -> str | None:
    """One header as plain text, or None.

    `str()` on a `policy.default` header object performs RFC 2047 decoding,
    which can raise on malformed encoded-words in hostile mail — so it is
    guarded. A header that will not decode is recorded as absent rather
    than crashing the parse of an entire exhibit.
    """
    try:
        value = msg.get(name)
        if value is None:
            return None
        text = str(value).strip()
        # Fold embedded CR/LF: a decoded header containing a newline would
        # let a crafted exhibit forge extra fields in any log or report
        # that prints headers one per line.
        return " ".join(text.split()) or None
    except (ValueError, TypeError, LookupError, UnicodeError):
        return None


def parse_eml(data: bytes, *, trusted: tuple[str, ...] | None = None) -> ParsedEmail:
    """Parse an RFC 5322 message into forensic fields.

    Never renders, never fetches, never executes. The HTML body is recorded
    as *present* and its text extracted; the markup itself stays in the
    exhibit, where invariant 10 keeps it (docs/19 §5 — rendering it fires
    the actor's tracking pixel from the investigator's IP).

    Malformed input degrades into `gaps` rather than raising, because a BEC
    exhibit is by definition attacker-authored and "the parser crashed" is
    not an acceptable answer to "what does this mail say".
    """
    if len(data) > MAX_EML_BYTES:
        raise DeceptionError(
            f"message is {len(data)} bytes, over the {MAX_EML_BYTES} cap")

    out = ParsedEmail()
    try:
        msg = email.message_from_bytes(data, policy=email.policy.default)
    except Exception as exc:                                  # noqa: BLE001
        # Genuinely anything: the email package raises a wide and
        # version-dependent set on hostile input. Invariant 12 — the
        # exhibit is still recorded, with the failure attached.
        out.gaps.append({"step": "parse", "reason": f"{type(exc).__name__}: {exc}"})
        return out

    out.message_id = _header_str(msg, "Message-ID")
    out.subject = _header_str(msg, "Subject")
    out.header_return_path = _first_addr(_header_str(msg, "Return-Path"))
    out.in_reply_to = _header_str(msg, "In-Reply-To")

    raw_from = _header_str(msg, "From")
    if raw_from:
        pairs = getaddresses([raw_from])
        if pairs:
            out.header_from_display = (pairs[0][0] or None)
            out.header_from = (pairs[0][1] or None)
    out.header_reply_to = _first_addr(_header_str(msg, "Reply-To"))
    out.header_to = _all_addrs(_header_str(msg, "To"))
    out.header_cc = _all_addrs(_header_str(msg, "Cc"))

    raw_date = _header_str(msg, "Date")
    if raw_date:
        try:
            out.date_header = parsedate_to_datetime(raw_date)
        except (ValueError, TypeError):
            out.gaps.append({"step": "date", "reason": f"unparseable: {raw_date[:120]}"})

    # -- authentication results -----------------------------------------
    try:
        auth_headers = msg.get_all("Authentication-Results") or []
    except Exception:                                         # noqa: BLE001
        auth_headers = []
    if auth_headers:
        # ONLY THE FIRST HEADER IS EVIDENCE. The rest are recorded and not
        # believed.
        #
        # Found by an adversarial pass, 2026-07-26, and it was the same
        # mistake this module gets RIGHT for `Received` and then made in
        # the inverse direction here. An MTA PREPENDS, so index 0 is the
        # receiving organisation's own verdict and anything the sender put
        # in the message they wrote is LAST. `_apply_auth_results` built a
        # dict comprehension over the joined string, which is last-wins —
        # so an attacker appending their own `Authentication-Results:
        # dkim=pass header.d=microsoft.com` had it override the real
        # `dkim=fail`, and `microsoft.com` came out as a **durable,
        # cryptographically authenticated** DOMAIN selector.
        #
        # That defeats this module's own rule 2 and invariant 9 using
        # bytes the attacker typed. The `email_dkim_domain_needs_pass`
        # CHECK could not catch it either: the parser made the result and
        # the domain agree on the forged value, which is exactly the
        # shape of the Phase 7 forged-PGP-verdict defect (docs/17) — a
        # constraint defends against the application forgetting to check,
        # never against it checking a forged input.
        #
        # The whole set is still stored in `auth_results_raw`, because a
        # message carrying two of these is itself a finding.
        out.auth_results_raw = " | ".join(str(a) for a in auth_headers)[:8000]
        _apply_auth_results(out, str(auth_headers[0]))
        if len(auth_headers) > 1:
            out.gaps.append({
                "step": "authentication_results",
                "reason": f"{len(auth_headers)} Authentication-Results "
                          "headers were present; only the first (the "
                          "receiving MTA's) was believed. The others are "
                          "in auth_results_raw and are attacker-writable — "
                          "a message carrying a second one is suspicious in "
                          "itself."})
    else:
        out.gaps.append({
            "step": "authentication_results",
            "reason": "no Authentication-Results header — SPF/DKIM/DMARC "
                      "were not evaluated by anything that wrote to this "
                      "message, so their absence is not a failure"})

    # -- the Received chain ---------------------------------------------
    try:
        received = [str(h) for h in (msg.get_all("Received") or [])][:_MAX_HEADERS]
    except Exception:                                         # noqa: BLE001
        received = []
    out.hops = parse_received_chain(received, trusted)
    if not received:
        out.gaps.append({"step": "received_chain",
                         "reason": "no Received headers; the message was not "
                                   "captured in transit"})

    # -- body and attachments -------------------------------------------
    _walk_parts(msg, out)
    if out.body_text:
        seen: set[str] = set()
        for match in _URL_RE.finditer(out.body_text):
            url = match.group(0).rstrip(".,;:!?")
            if url not in seen:
                seen.add(url)
                out.extracted_urls.append(url)
            if len(out.extracted_urls) >= 500:
                out.gaps.append({"step": "url_extraction",
                                 "reason": "capped at 500 URLs"})
                break
    return out


def _first_addr(raw: str | None) -> str | None:
    if not raw:
        return None
    pairs = getaddresses([raw])
    return (pairs[0][1] or None) if pairs else None


def _all_addrs(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [a for _, a in getaddresses([raw]) if a][:200]


def _apply_auth_results(out: ParsedEmail, raw: str) -> None:
    """Read SPF/DKIM/DMARC verdicts out of `Authentication-Results`.

    ## A domain is recorded only when the method PASSED

    This is the invariant-9 rule in its email form and the DB enforces the
    DKIM half (`email_dkim_domain_needs_pass`). `header.d=microsoft.com`
    on a FAILING signature is a claim by the attacker, not an identity —
    recording it would invite every downstream reader, and every report,
    to treat a forgery as authenticated.

    ## The result and the domain are decided TOGETHER, per method

    A message may legitimately carry more than one signature for the same
    method — a mailing list or a forwarder re-signs, so
    `dkim=pass header.d=acme.example; dkim=fail header.d=list.example` is
    ordinary mail, not an attack.

    The previous version read the RESULT from a last-wins dict over the
    whole string and the DOMAIN from whichever clause passed, so that
    input produced `dkim_result = FAIL` alongside
    `dkim_domain = acme.example`. That combination violates
    `email_dkim_domain_needs_pass`, and the violation surfaced as a raw
    `CheckViolation` — a 500 — AFTER `EvidenceService.ingest` had already
    committed the WORM exhibit in its own transaction. Net result: an
    object-locked, retention-committed exhibit with no `email_message`
    describing it and nothing in the dead letter. `parse_eml`'s own
    docstring says the parser must not crash on hostile input; it was
    crashing on *well-formed* input.

    So each method is resolved once, over its own clauses:
    **any PASS wins, and carries its own domain.** That is also the
    correct reading — one valid signature is a valid signature — and it
    makes the constraint satisfiable by construction rather than by luck.
    """
    known = {"spf": {"PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE",
                     "TEMPERROR", "PERMERROR"},
             "dkim": {"PASS", "FAIL", "NONE", "TEMPERROR", "PERMERROR"},
             "dmarc": {"PASS", "FAIL", "NONE", "TEMPERROR", "PERMERROR"}}
    # method -> (result, domain-or-None), built clause by clause so
    # `spf=pass smtp.mailfrom=a.com; dkim=fail header.d=b.com` cannot
    # attribute b.com to SPF.
    found: dict[str, tuple[str, str | None]] = {}
    for clause in raw.split(";"):
        method = _AUTH_RESULT.search(clause)
        if not method:
            continue
        name, result = method.group(1).lower(), method.group(2).upper()
        if name not in known or result not in known[name]:
            continue
        domain_match = _AUTH_DOMAIN.search(clause)
        value = None
        if domain_match:
            value = (_domain_of("@" + domain_match.group(1))
                     or domain_match.group(1).lower())
        previous = found.get(name)
        # A PASS beats anything already seen; otherwise the first verdict
        # stands. Never record a domain for a non-PASS: `header.d=` on a
        # failing signature is a claim by the attacker, not an identity.
        if previous is None or (result == "PASS" and previous[0] != "PASS"):
            found[name] = (result, value if result == "PASS" else None)

    out.spf_result, out.spf_domain = found.get("spf", (None, None))
    out.dkim_result, out.dkim_domain = found.get("dkim", (None, None))
    out.dmarc_result, out.dmarc_domain = found.get("dmarc", (None, None))


def _walk_parts(msg: EmailMessage, out: ParsedEmail) -> None:
    """Collect body text and attachment METADATA.

    Attachment bytes are not returned. A BEC attachment is malware and
    belongs in `lab.sample`, behind the policy gate and the separate
    origin that already exist — giving it a second, unguarded home here
    would be invariant 10 undone by convenience.
    """
    texts: list[str] = []
    count = 0
    try:
        parts = list(msg.walk())
    except Exception as exc:                                  # noqa: BLE001
        out.gaps.append({"step": "mime_walk", "reason": f"{type(exc).__name__}: {exc}"})
        return
    for part in parts[:_MAX_PARTS]:
        count += 1
        try:
            ctype = (part.get_content_type() or "").lower()
            disposition = (part.get_content_disposition() or "").lower()
            filename = part.get_filename()
        except Exception:                                     # noqa: BLE001
            out.gaps.append({"step": "mime_part", "reason": "unreadable headers"})
            continue

        if disposition == "attachment" or (filename and ctype != "text/plain"):
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:                                 # noqa: BLE001
                payload = b""
            out.attachments.append({
                "filename": filename,
                "media_type": ctype or None,
                "byte_size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
                "is_inline": False,
                "content_id": part.get("Content-ID"),
            })
            continue

        if ctype == "text/html":
            out.has_html_body = True
            continue                      # markup stays in the exhibit
        if ctype == "text/plain":
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    texts.append(payload.decode(
                        part.get_content_charset() or "utf-8", errors="replace"))
            except (LookupError, ValueError, UnicodeError):
                out.gaps.append({"step": "body_decode",
                                 "reason": "undecodable text/plain part"})
    if len(parts) > _MAX_PARTS:
        out.gaps.append({"step": "mime_walk",
                         "reason": f"capped at {_MAX_PARTS} of {len(parts)} parts"})
    if texts:
        out.body_text = "\n".join(texts)[:1_000_000]
    elif out.has_html_body:
        out.gaps.append({
            "step": "body_text",
            "reason": "HTML-only body: the markup is in the exhibit and is "
                      "never rendered, so no plain text was available"})


# ---------------------------------------------------------------------------
# Presented-vs-durable (invariant 9, docs/19 §1.2)
# ---------------------------------------------------------------------------

def selector_candidates_for_call(call: dict) -> list[dict]:
    """Selector proposals from a call record — DELIBERATELY not including
    the presented number.

    The number the victim's handset showed is chosen by the attacker.
    Minting a strong `PHONE` selector from it puts a real subscriber's
    number on a criminal actor's node with confidence, which attributes a
    crime to whoever the attacker picked out of the air. That is the
    fund-losing bug of this subsystem and it is prevented here, in the one
    function that decides what becomes a selector, rather than by asking
    every caller to remember.

    `p_asserted_identity` is set by the trusted network. `originating_trunk`
    is what actually offered the call. Those are durable. The presented
    number is returned nowhere.

    A STIR/SHAKEN attestation of A, and only when actually verified, is the
    one case where the presented number has been vouched for by the
    originating carrier — and even then it is offered as a WEAK candidate,
    because an attestation says "this caller may use this number", not
    "this caller is that person".
    """
    out: list[dict] = []
    pai = (call.get("p_asserted_identity") or "").strip()
    if pai:
        kind = "SIP_URI" if pai.lower().startswith(("sip:", "sips:", "tel:")) else "PHONE"
        out.append({"selector_type": kind, "value": pai, "strength": "durable",
                    "why": "P-Asserted-Identity is set by the trusted network"})
    for uri_field in ("sip_from_uri", "sip_to_uri"):
        value = (call.get(uri_field) or "").strip()
        if value:
            out.append({"selector_type": "SIP_URI", "value": value,
                        "strength": "durable",
                        "why": f"{uri_field} came from the trunk, not the display"})
    called = (call.get("called_number_e164") or "").strip()
    if called:
        out.append({"selector_type": "PHONE", "value": called,
                    "strength": "durable",
                    "why": "the called party is not attacker-chosen"})
    if (call.get("stir_shaken_attestation") == "A"
            and call.get("stir_shaken_verified")
            and call.get("presented_number_e164")):
        out.append({"selector_type": "PHONE",
                    "value": call["presented_number_e164"],
                    "strength": "weak",
                    "why": "STIR/SHAKEN attestation A, verified: the "
                           "originating carrier vouches the caller may use "
                           "this number — not that they are its subscriber"})
    return out


def selector_candidates_for_email(parsed: ParsedEmail) -> list[dict]:
    """Selector proposals from a parsed message.

    `header_from` is offered WEAK and never strong: it is the field BEC
    forges. A DKIM domain appears only when DKIM passed, which is the one
    cryptographic statement in an email header.
    """
    out: list[dict] = []
    if parsed.dkim_domain and parsed.dkim_result == "PASS":
        out.append({"selector_type": "DOMAIN", "value": parsed.dkim_domain,
                    "strength": "durable",
                    "why": "DKIM PASSED for this domain — the only "
                           "cryptographically authenticated field in the mail"})
    if parsed.header_from:
        out.append({"selector_type": "EMAIL", "value": parsed.header_from,
                    "strength": "weak",
                    "why": "From: is the field BEC forges; unauthenticated"})
    if parsed.header_reply_to:
        out.append({"selector_type": "EMAIL", "value": parsed.header_reply_to,
                    "strength": "weak",
                    "why": "Reply-To: is where a reply actually goes, which "
                           "is often the only real address in a BEC mail"})
    if parsed.message_id:
        out.append({"selector_type": "EMAIL_MSGID", "value": parsed.message_id,
                    "strength": "weak",
                    "why": "attacker-generated: fingerprints the sending kit, "
                           "never the sender"})
    # Infrastructure ONLY from at-or-below the trust boundary — and ONLY
    # when a boundary was actually established.
    #
    # With no `NOCTORNAL_TRUSTED_MTA_HOSTS` configured, the boundary
    # defaults to seq 0. That default is right for what to EXCLUDE, and it
    # was silently wrong for what to include: hop 0 is the receiving
    # organisation's own MTA, so its `from_ip` is a machine INSIDE the
    # victim's network. This function was therefore offering
    # `10.1.2.3` — the victim's internal relay — as durable infrastructure
    # to attach to the criminal actor, while suppressing the attacker's
    # real sending IP one hop above it. Precisely inverted.
    #
    # Unconfigured means unknown, and the honest output for unknown is
    # nothing. An operator who sets the variable gets the real answer.
    if parsed.hops and all(h.boundary_is_assumed for h in parsed.hops):
        out.append({"selector_type": None, "value": None, "strength": "none",
                    "why": "no infrastructure proposed: no trusted MTA was "
                           "recognised in this chain (see "
                           "NOCTORNAL_TRUSTED_MTA_HOSTS), so this system "
                           "cannot tell an observation from a claim. Hop 0 "
                           "is the recipient's OWN server; proposing its "
                           "address would attach the victim's internal "
                           "relay to the actor."})
        return out
    boundary = _boundary_seq(parsed.hops)
    for hop in parsed.hops:
        if hop.seq > boundary:
            break
        if hop.from_ip:
            out.append({"selector_type": "IPV4" if "." in hop.from_ip else "IPV6",
                        "value": hop.from_ip, "strength": "durable",
                        "why": f"Received hop {hop.seq}, at or inside the "
                               f"trusted boundary — written by infrastructure "
                               f"the recipient controls, so it is an "
                               f"observation rather than a claim"})
    return out


def _boundary_seq(hops: list[Hop]) -> int:
    for hop in hops:
        if hop.is_trusted_boundary:
            return hop.seq
    return 0


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

_CAPTURE_COLUMNS = (
    "id, case_id, requested_url, requested_url_norm, final_url, final_url_norm, "
    "captured_at, capture_method, capture_tool, egress_profile_id, user_agent, "
    "viewport, http_status, is_live, page_title, favicon_hash, "
    "screenshot_evidence_id, dom_evidence_id, har_evidence_id, tls_subject, "
    "tls_issuer, tls_not_before, tls_not_after, tls_spki_sha256, "
    "submitted_input, submission_authority_ref, captured_by, note, "
    "classification, compartments, legal_hold"
)
_CAPTURE_Q = ", ".join("x." + c.strip() for c in _CAPTURE_COLUMNS.split(","))

_EMAIL_COLUMNS = (
    "id, case_id, evidence_id, message_id, message_id_norm, header_from, "
    "header_from_display, header_reply_to, header_return_path, envelope_from, "
    "header_to, header_cc, subject, date_header, spf_result, spf_domain, "
    "dkim_result, dkim_domain, dmarc_result, dmarc_domain, "
    "from_replyto_divergent, from_returnpath_divergent, "
    "display_name_impersonates, reply_to_is_freemail, body_text, "
    "has_html_body, extracted_urls, direction, recorded_by, recorded_at, "
    "parse_gaps, classification, compartments, legal_hold"
)
_EMAIL_Q = ", ".join("x." + c.strip() for c in _EMAIL_COLUMNS.split(","))

_CALL_COLUMNS = (
    "id, case_id, presented_number, presented_number_e164, presented_name, "
    "originating_trunk, p_asserted_identity, carrier_name, "
    "stir_shaken_attestation, stir_shaken_verified, called_number_e164, "
    "direction, started_at, ended_at, duration_seconds, disposition, "
    "sip_call_id, sip_from_uri, sip_to_uri, source_ip, record_source, "
    "evidence_id, recording_evidence_id, recording_lawful_basis, note, "
    "recorded_by, recorded_at, classification, compartments, legal_hold"
)
_CALL_Q = ", ".join("x." + c.strip() for c in _CALL_COLUMNS.split(","))


def _labels_clause(alias: str = "x") -> str:
    """The composed-label filter every read in this module uses.

    Composed, not the row's own: an element can be classified ABOVE its
    case (so the case gate alone is insufficient) and a case reclassified
    upward after the fact must take its contents with it (so the row's own
    labels alone are insufficient). Written once and interpolated, for the
    same reason `notifications.readable_predicate` exists — F19 found three
    separate label holes that all shared the root "the rule was enforced in
    one place and absent in the second".
    """
    return f"""
        greatest({alias}.classification,
                 coalesce(c.classification, {alias}.classification)) <= %s::core.tlp
        AND ({alias}.compartments || coalesce(c.compartments, '{{}}')) <@ %s
    """


class DeceptionService:
    """Reads and writes for phishing captures, BEC email and vishing calls.

    Every read composes the element's labels with its case's; every write
    raises the element to the case floor before inserting, which the
    `enforce_tlp_floor` trigger then backstops. Both halves, because F19
    established that a rule living only in application code holds exactly
    until somebody writes the second caller.
    """

    def __init__(self, conn: psycopg.Connection, *, now=_utcnow):
        self._c = conn
        self._now = now

    # -- captures --------------------------------------------------------
    def record_capture(self, *, case_id: UUID, requested_url: str,
                       capture_method: str, captured_by: UUID,
                       final_url: str | None = None,
                       hops: list[dict] | None = None,
                       egress_profile_id: UUID | None = None,
                       screenshot_evidence_id: UUID | None = None,
                       dom_evidence_id: UUID | None = None,
                       har_evidence_id: UUID | None = None,
                       tls: dict | None = None,
                       submitted_input: bool = False,
                       submission_authority_ref: str | None = None,
                       classification: str = "AMBER",
                       compartments: frozenset[str] = frozenset(),
                       **extra) -> UUID:
        """Record one capture and its redirect chain, atomically.

        The chain is inserted in the same transaction as the capture. A
        capture row whose hops are missing because a second call failed
        would read as "this URL redirected nowhere", which is a finding —
        and a false one. Invariant 12's principle: an absence with no
        reason is indistinguishable from an observation.
        """
        from noctornal_ontology.normalisers import url_norm

        if submitted_input and not (submission_authority_ref or "").strip():
            raise DeceptionError(
                "submitting input to a phishing page — including canary "
                "credentials — may constitute unauthorised access and is "
                "legal item L5. Record the written authority reference or "
                "do not record the submission.")

        classification, compartments = self._raise_to_case_floor(
            case_id, classification, compartments)

        with self._c.transaction():
            row = self._c.execute(
                """INSERT INTO deception.capture
                        (case_id, requested_url, requested_url_norm, final_url,
                         final_url_norm, capture_method, capture_tool,
                         egress_profile_id, user_agent, viewport, http_status,
                         is_live, page_title, visible_text, favicon_hash,
                         screenshot_evidence_id, dom_evidence_id,
                         har_evidence_id, tls_subject, tls_issuer,
                         tls_not_before, tls_not_after, tls_spki_sha256,
                         submitted_input, submission_authority_ref,
                         captured_by, note, classification, compartments)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING id""",
                (case_id, requested_url, url_norm(requested_url), final_url,
                 url_norm(final_url) if final_url else None, capture_method,
                 extra.get("capture_tool"), egress_profile_id,
                 extra.get("user_agent"), extra.get("viewport"),
                 extra.get("http_status"), extra.get("is_live"),
                 extra.get("page_title"), extra.get("visible_text"),
                 extra.get("favicon_hash"), screenshot_evidence_id,
                 dom_evidence_id, har_evidence_id,
                 (tls or {}).get("subject"), (tls or {}).get("issuer"),
                 (tls or {}).get("not_before"), (tls or {}).get("not_after"),
                 (tls or {}).get("spki_sha256"), submitted_input,
                 submission_authority_ref, captured_by, extra.get("note"),
                 classification, sorted(compartments)),
            ).fetchone()
            capture_id = row[0]
            for seq, hop in enumerate(hops or []):
                self._c.execute(
                    """INSERT INTO deception.capture_hop
                           (capture_id, seq, url, url_norm, http_status,
                            resolved_ip, asn, server_header, hop_kind)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (capture_id, seq, hop["url"], url_norm(hop["url"]),
                     hop.get("http_status"), hop.get("resolved_ip"),
                     hop.get("asn"), hop.get("server_header"),
                     hop.get("hop_kind", "HTTP_30X")))
            self._audit("CAPTURE_RECORDED", captured_by, capture_id, case_id,
                        {"requested_url": requested_url,
                         "method": capture_method,
                         "submitted_input": submitted_input})
        return capture_id

    def captures(self, case_id: UUID, *, clearance: str,
                 compartments: frozenset[str] = frozenset(),
                 limit: int = 100) -> list[dict]:
        rows = self._c.execute(
            f"""SELECT {_CAPTURE_Q} FROM deception.capture x
                  LEFT JOIN core."case" c ON c.id = x.case_id
                 WHERE x.case_id = %s AND {_labels_clause()}
                 ORDER BY x.captured_at DESC LIMIT %s""",
            (case_id, clearance, list(compartments), limit)).fetchall()
        return [_capture_row(r) for r in rows]

    def capture(self, capture_id: UUID, *, clearance: str,
                compartments: frozenset[str] = frozenset()) -> dict | None:
        """One capture, or None if the caller may not know it exists.

        None rather than a raise, so the router's answer is identical to
        "no such capture" — a status code must not be an existence oracle
        for a compartmented case (rule (b) of the access gate).
        """
        row = self._c.execute(
            f"""SELECT {_CAPTURE_Q} FROM deception.capture x
                  LEFT JOIN core."case" c ON c.id = x.case_id
                 WHERE x.id = %s AND {_labels_clause()}""",
            (capture_id, clearance, list(compartments))).fetchone()
        if row is None:
            return None
        out = _capture_row(row)
        out["hops"] = [
            {"seq": h[0], "url": h[1], "url_defanged": defang(h[1]),
             "http_status": h[2], "resolved_ip": str(h[3]) if h[3] else None,
             "asn": h[4], "server_header": h[5], "hop_kind": h[6]}
            for h in self._c.execute(
                """SELECT seq, url, http_status, resolved_ip, asn,
                          server_header, hop_kind
                     FROM deception.capture_hop
                    WHERE capture_id = %s ORDER BY seq""",
                (capture_id,)).fetchall()]
        return out

    # -- email -----------------------------------------------------------
    def record_email(self, *, case_id: UUID, evidence_id: UUID,
                     parsed: ParsedEmail, recorded_by: UUID,
                     direction: str = "INBOUND_TO_VICTIM",
                     envelope_from: str | None = None,
                     display_name_impersonates: str | None = None,
                     victim_node_id: UUID | None = None,
                     classification: str = "AMBER",
                     compartments: frozenset[str] = frozenset()) -> UUID:
        """Persist a parsed message, its hop chain and its attachment
        metadata, atomically."""
        from noctornal_ontology.normalisers import msgid_norm

        classification, compartments = self._raise_to_case_floor(
            case_id, classification, compartments)

        with self._c.transaction():
            row = self._c.execute(
                """INSERT INTO deception.email_message
                       (case_id, evidence_id, message_id, message_id_norm,
                        header_from, header_from_display, header_reply_to,
                        header_return_path, envelope_from, header_to,
                        header_cc, subject, date_header, in_reply_to,
                        spf_result, spf_domain, dkim_result, dkim_domain,
                        dmarc_result, dmarc_domain, auth_results_raw,
                        from_replyto_divergent, from_returnpath_divergent,
                        display_name_impersonates, reply_to_is_freemail,
                        body_text, has_html_body, extracted_urls, direction,
                        victim_node_id, recorded_by, parse_gaps,
                        classification, compartments)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                           %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                           %s,%s)
                   RETURNING id""",
                (case_id, evidence_id, parsed.message_id,
                 msgid_norm(parsed.message_id) if parsed.message_id else None,
                 parsed.header_from, parsed.header_from_display,
                 parsed.header_reply_to, parsed.header_return_path,
                 envelope_from, parsed.header_to, parsed.header_cc,
                 parsed.subject, parsed.date_header, parsed.in_reply_to,
                 parsed.spf_result, parsed.spf_domain, parsed.dkim_result,
                 parsed.dkim_domain, parsed.dmarc_result, parsed.dmarc_domain,
                 parsed.auth_results_raw, parsed.from_replyto_divergent,
                 parsed.from_returnpath_divergent, display_name_impersonates,
                 parsed.reply_to_is_freemail, parsed.body_text,
                 parsed.has_html_body, parsed.extracted_urls, direction,
                 victim_node_id, recorded_by, Json(parsed.gaps),
                 classification, sorted(compartments)),
            ).fetchone()
            message_id = row[0]
            for hop in parsed.hops:
                self._c.execute(
                    """INSERT INTO deception.email_hop
                           (message_id, seq, received_raw, from_host, from_ip,
                            by_host, protocol, tls_used, received_at,
                            is_trusted_boundary)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (message_id, hop.seq, hop.raw, hop.from_host,
                     hop.from_ip, hop.by_host, hop.protocol, hop.tls_used,
                     hop.received_at, hop.is_trusted_boundary))
            for att in parsed.attachments:
                self._c.execute(
                    """INSERT INTO deception.email_attachment
                           (message_id, filename, media_type, byte_size,
                            sha256, is_inline, content_id)
                       VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                    (message_id, att.get("filename"), att.get("media_type"),
                     att.get("byte_size"),
                     bytes.fromhex(att["sha256"]) if att.get("sha256") else None,
                     att.get("is_inline", False), att.get("content_id")))
            self._audit("EMAIL_RECORDED", recorded_by, message_id, case_id,
                        {"from": parsed.header_from,
                         "divergent": parsed.from_replyto_divergent})
        return message_id

    def emails(self, case_id: UUID, *, clearance: str,
               compartments: frozenset[str] = frozenset(),
               divergent_only: bool = False, limit: int = 100) -> list[dict]:
        rows = self._c.execute(
            f"""SELECT {_EMAIL_Q} FROM deception.email_message x
                  LEFT JOIN core."case" c ON c.id = x.case_id
                 WHERE x.case_id = %s AND {_labels_clause()}
                   AND (%s = false OR x.from_replyto_divergent)
                 ORDER BY x.recorded_at DESC LIMIT %s""",
            (case_id, clearance, list(compartments), divergent_only,
             limit)).fetchall()
        return [_email_row(r) for r in rows]

    def email(self, message_id: UUID, *, clearance: str,
              compartments: frozenset[str] = frozenset()) -> dict | None:
        row = self._c.execute(
            f"""SELECT {_EMAIL_Q} FROM deception.email_message x
                  LEFT JOIN core."case" c ON c.id = x.case_id
                 WHERE x.id = %s AND {_labels_clause()}""",
            (message_id, clearance, list(compartments))).fetchone()
        if row is None:
            return None
        out = _email_row(row)
        hop_rows = self._c.execute(
            """SELECT seq, from_host, from_ip, by_host, protocol, tls_used,
                      received_at, is_trusted_boundary, received_raw
                 FROM deception.email_hop
                WHERE message_id = %s ORDER BY seq""",
            (message_id,)).fetchall()
        # The boundary is a property of the CHAIN, so it is resolved once
        # here rather than by a correlated subquery per row. Absent a
        # marked boundary the answer is seq 0 — the same conservative
        # default `parse_received_chain` applies, and the two must agree
        # or the UI would draw the line in a different place from the
        # extractor.
        boundary = next((h[0] for h in hop_rows if h[7]), 0)
        out["trusted_boundary_seq"] = boundary
        out["hops"] = [
            {"seq": h[0], "from_host": h[1],
             "from_ip": str(h[2]) if h[2] else None, "by_host": h[3],
             "protocol": h[4], "tls_used": h[5],
             "received_at": h[6].isoformat() if h[6] else None,
             "is_trusted_boundary": h[7], "raw": h[8],
             # Stated per-row so the UI does not have to re-derive the
             # rule, and cannot re-derive it wrongly.
             "is_attacker_writable": h[0] > boundary}
            for h in hop_rows]
        out["attachments"] = [
            {"filename": a[0], "media_type": a[1], "byte_size": a[2],
             "sha256": bytes(a[3]).hex() if a[3] else None,
             "sample_id": str(a[4]) if a[4] else None}
            for a in self._c.execute(
                """SELECT filename, media_type, byte_size, sha256, sample_id
                     FROM deception.email_attachment WHERE message_id = %s
                    ORDER BY filename""", (message_id,)).fetchall()]
        return out

    # -- calls -----------------------------------------------------------
    def record_call(self, *, case_id: UUID, started_at: datetime,
                    direction: str, record_source: str, recorded_by: UUID,
                    recording_evidence_id: UUID | None = None,
                    recording_lawful_basis: str | None = None,
                    classification: str = "AMBER",
                    compartments: frozenset[str] = frozenset(),
                    **fields) -> UUID:
        """Record one call.

        The lawful-basis check is repeated here even though the DB has a
        CHECK constraint, so the caller gets a sentence explaining L4
        rather than a constraint-violation traceback. The constraint stays
        because a migration or a psql session does not run this code.
        """
        if recording_evidence_id is not None and not (recording_lawful_basis or "").strip():
            raise DeceptionError(
                "a call recording is intercepted content, not metadata "
                "(legal item L4). Record the lawful basis under which it "
                "was obtained, or attach the CDR without the recording.")

        classification, compartments = self._raise_to_case_floor(
            case_id, classification, compartments)

        with self._c.transaction():
            row = self._c.execute(
                """INSERT INTO deception.call_record
                       (case_id, presented_number, presented_number_e164,
                        presented_name, originating_trunk, p_asserted_identity,
                        carrier_name, stir_shaken_attestation,
                        stir_shaken_verified, called_number_e164, direction,
                        started_at, ended_at, duration_seconds, disposition,
                        sip_call_id, sip_from_uri, sip_to_uri, source_ip,
                        user_agent, record_source, evidence_id,
                        recording_evidence_id, recording_lawful_basis,
                        victim_node_id, lure_node_id, note, recorded_by,
                        classification, compartments)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                           %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   RETURNING id""",
                (case_id, fields.get("presented_number"),
                 fields.get("presented_number_e164"),
                 fields.get("presented_name"), fields.get("originating_trunk"),
                 fields.get("p_asserted_identity"), fields.get("carrier_name"),
                 fields.get("stir_shaken_attestation"),
                 bool(fields.get("stir_shaken_verified", False)),
                 fields.get("called_number_e164"), direction, started_at,
                 fields.get("ended_at"), fields.get("duration_seconds"),
                 fields.get("disposition"), fields.get("sip_call_id"),
                 fields.get("sip_from_uri"), fields.get("sip_to_uri"),
                 fields.get("source_ip"), fields.get("user_agent"),
                 record_source, fields.get("evidence_id"),
                 recording_evidence_id, recording_lawful_basis,
                 fields.get("victim_node_id"), fields.get("lure_node_id"),
                 fields.get("note"), recorded_by, classification,
                 sorted(compartments)),
            ).fetchone()
            call_id = row[0]
            self._audit("CALL_RECORDED", recorded_by, call_id, case_id,
                        {"record_source": record_source,
                         "has_recording": recording_evidence_id is not None})
        return call_id

    def calls(self, case_id: UUID, *, clearance: str,
              compartments: frozenset[str] = frozenset(),
              limit: int = 100) -> list[dict]:
        rows = self._c.execute(
            f"""SELECT {_CALL_Q} FROM deception.call_record x
                  LEFT JOIN core."case" c ON c.id = x.case_id
                 WHERE x.case_id = %s AND {_labels_clause()}
                 ORDER BY x.started_at DESC LIMIT %s""",
            (case_id, clearance, list(compartments), limit)).fetchall()
        return [_call_row(r) for r in rows]

    # -- internal --------------------------------------------------------
    def _raise_to_case_floor(self, case_id: UUID, classification: str,
                             compartments: frozenset[str]
                             ) -> tuple[str, frozenset[str]]:
        """Never below the case, and always carrying the case's compartments.

        The `enforce_tlp_floor` trigger would reject a row below the floor;
        raising here means the caller gets the row they asked for at the
        right label instead of a constraint error, and — the part the
        trigger cannot do — the case's compartments come along.
        """
        try:
            tlp_from_name(classification)
        except AccessResolutionError as exc:
            raise DeceptionError(f"unknown classification {classification!r}") from exc
        case = self._c.execute(
            'SELECT classification, compartments FROM core."case" WHERE id = %s',
            (case_id,)).fetchone()
        if case is None:
            raise DeceptionError("no such case")
        classification = max(tlp_from_name(classification),
                             tlp_from_name(case[0])).name
        return classification, frozenset(compartments) | frozenset(case[1] or [])

    def _audit(self, action, actor_id, object_id, case_id, detail) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'deception', %s, %s, %s)""",
            (actor_id, action, object_id, case_id, Json(detail)))


def _capture_row(r) -> dict:
    return {
        "id": str(r[0]), "case_id": str(r[1]),
        "requested_url": r[2], "requested_url_defanged": defang(r[2]),
        "requested_url_norm": r[3],
        "final_url": r[4], "final_url_defanged": defang(r[4]) if r[4] else None,
        "final_url_norm": r[5],
        "captured_at": r[6].isoformat(), "capture_method": r[7],
        "capture_tool": r[8],
        "egress_profile_id": str(r[9]) if r[9] else None,
        "user_agent": r[10], "viewport": r[11], "http_status": r[12],
        "is_live": r[13], "page_title": r[14], "favicon_hash": r[15],
        "screenshot_evidence_id": str(r[16]) if r[16] else None,
        "dom_evidence_id": str(r[17]) if r[17] else None,
        "har_evidence_id": str(r[18]) if r[18] else None,
        "tls_subject": r[19], "tls_issuer": r[20],
        "tls_not_before": r[21].isoformat() if r[21] else None,
        "tls_not_after": r[22].isoformat() if r[22] else None,
        "tls_spki_sha256": bytes(r[23]).hex() if r[23] else None,
        "submitted_input": r[24], "submission_authority_ref": r[25],
        "captured_by": str(r[26]), "note": r[27],
        "classification": r[28], "compartments": sorted(r[29] or []),
        "legal_hold": r[30],
    }


def _email_row(r) -> dict:
    return {
        "id": str(r[0]), "case_id": str(r[1]), "evidence_id": str(r[2]),
        "message_id": r[3], "message_id_norm": r[4],
        "header_from": r[5], "header_from_display": r[6],
        "header_reply_to": r[7], "header_return_path": r[8],
        "envelope_from": r[9], "header_to": r[10] or [], "header_cc": r[11] or [],
        "subject": r[12],
        "date_header": r[13].isoformat() if r[13] else None,
        "spf_result": r[14], "spf_domain": r[15],
        "dkim_result": r[16], "dkim_domain": r[17],
        "dmarc_result": r[18], "dmarc_domain": r[19],
        "from_replyto_divergent": r[20], "from_returnpath_divergent": r[21],
        "display_name_impersonates": r[22], "reply_to_is_freemail": r[23],
        "body_text": r[24], "has_html_body": r[25],
        "extracted_urls": r[26] or [],
        "extracted_urls_defanged": [defang(u) for u in (r[26] or [])],
        "direction": r[27], "recorded_by": str(r[28]),
        "recorded_at": r[29].isoformat(), "parse_gaps": r[30] or [],
        "classification": r[31], "compartments": sorted(r[32] or []),
        "legal_hold": r[33],
    }


def _call_row(r) -> dict:
    return {
        "id": str(r[0]), "case_id": str(r[1]),
        # Kept nested so no consumer can mistake it for an established
        # identity: the shape of the response says "presented".
        "presented": {"number": r[2], "number_e164": r[3], "name": r[4],
                      "is_attacker_controlled": True},
        "durable": {"originating_trunk": r[5], "p_asserted_identity": r[6],
                    "carrier_name": r[7], "stir_shaken_attestation": r[8],
                    "stir_shaken_verified": r[9]},
        "called_number_e164": r[10], "direction": r[11],
        "started_at": r[12].isoformat(),
        "ended_at": r[13].isoformat() if r[13] else None,
        "duration_seconds": r[14], "disposition": r[15],
        "sip_call_id": r[16], "sip_from_uri": r[17], "sip_to_uri": r[18],
        "source_ip": str(r[19]) if r[19] else None,
        "record_source": r[20],
        "evidence_id": str(r[21]) if r[21] else None,
        "recording_evidence_id": str(r[22]) if r[22] else None,
        "recording_lawful_basis": r[23], "note": r[24],
        "recorded_by": str(r[25]), "recorded_at": r[26].isoformat(),
        "classification": r[27], "compartments": sorted(r[28] or []),
        "legal_hold": r[29],
    }


__all__ = [
    "FREEMAIL_DOMAINS", "HOSTILE_MEDIA_TYPES", "MAX_EML_BYTES",
    "DeceptionError", "DeceptionService", "Hop", "ParsedEmail",
    "defang", "is_hostile_media_type", "parse_eml", "parse_received_chain",
    "raster_type_of", "selector_candidates_for_call",
    "selector_candidates_for_email", "trusted_mta_suffixes",
]
