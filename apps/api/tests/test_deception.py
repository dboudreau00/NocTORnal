"""Social-engineering evidence: the pure logic (docs/19).

No database. These test the three rules that decide whether the subsystem
is safe, all of which live in pure functions so they CAN be tested without
one:

  * invariant 10 generalised — hostile markup, and a raster sniffer that
    does not believe the declared type;
  * invariant 9 generalised — the presented identifier never becomes a
    selector;
  * the Received chain is trustworthy inwards only.

Per `CONVENTIONS.md`, every invariant has a test named after it.
"""
from __future__ import annotations

from noctornal_api.deception import (
    HOSTILE_MEDIA_TYPES,
    ParsedEmail,
    defang,
    is_hostile_media_type,
    parse_eml,
    parse_received_chain,
    raster_type_of,
    selector_candidates_for_call,
    selector_candidates_for_email,
)

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64


# --- invariant 10: samples never render, never execute -------------------

def test_invariant_10_a_captured_dom_is_hostile_markup():
    """A saved phishing page is attacker-authored code. The whole reason
    `is_hostile_markup` exists."""
    assert is_hostile_media_type("text/html")
    assert is_hostile_media_type("text/html; charset=utf-8")
    assert is_hostile_media_type("message/rfc822")
    assert is_hostile_media_type("application/x-har")


def test_invariant_10_svg_is_code_that_happens_to_draw():
    """The one 'image' type that must never reach a render path. An SVG
    can carry <script>; a PNG cannot."""
    assert is_hostile_media_type("image/svg+xml")
    assert "image/svg+xml" in HOSTILE_MEDIA_TYPES
    assert raster_type_of(b"<svg xmlns='http://www.w3.org/2000/svg'>") is None


def test_invariant_10_the_declared_media_type_is_not_believed_on_read():
    """THE attack this subsystem's one inline path exists to survive.

    `core.evidence.media_type` is `UploadFile.content_type` — whatever the
    uploading client said. An HTML document labelled `image/png` must not
    be served as an image, so the read path re-derives the type from the
    bytes and refuses when they are not a raster image.
    """
    html = b"<html><script>fetch('/api/v1/cases')</script></html>"
    assert raster_type_of(html) is None
    assert raster_type_of(PNG) == "image/png"
    assert raster_type_of(JPEG) == "image/jpeg"


def test_a_raster_sniffer_that_returns_none_is_a_refusal_not_a_default():
    """None must mean "do not serve". If an empty body or junk resolved to
    some default type, the guard would be inverted for exactly the inputs
    it is there to catch."""
    assert raster_type_of(b"") is None
    assert raster_type_of(b"BM") is None          # too short to be a BMP
    assert raster_type_of(b"%PDF-1.7") is None
    assert raster_type_of(b"GIF89a" + b"\x00" * 20) == "image/gif"


# --- the Received chain is trustworthy inwards only ----------------------

CHAIN = [
    # seq 0: our own MTA. Trustworthy.
    "from mx-edge.corp.example (mx-edge.corp.example [10.0.0.5]) "
    "by mail.corp.example with ESMTPS id abc; Mon, 20 Jul 2026 09:00:03 +0000",
    # seq 1: still ours.
    "from relay.corp.example (relay.corp.example [10.0.0.9]) "
    "by mx-edge.corp.example with ESMTP id def; Mon, 20 Jul 2026 09:00:02 +0000",
    # seq 2: the first hop OUTSIDE. Attacker-writable from here up.
    "from evil-vps.example (evil-vps.example [203.0.113.7]) "
    "by relay.corp.example with ESMTP id ghi; Mon, 20 Jul 2026 09:00:01 +0000",
    # seq 3: pure fiction, typed by the sender.
    "from totally-microsoft.example ([198.51.100.1]) "
    "by evil-vps.example; Mon, 20 Jul 2026 09:00:00 +0000",
]


def test_the_received_chain_is_numbered_recipient_first():
    hops = parse_received_chain(CHAIN, trusted=("corp.example",))
    assert [h.seq for h in hops] == [0, 1, 2, 3]
    assert hops[0].by_host == "mail.corp.example"
    assert hops[0].from_ip == "10.0.0.5"
    assert hops[3].from_ip == "198.51.100.1"


def test_trust_stops_at_the_last_hop_our_own_infrastructure_wrote():
    """The test that matters, and the one whose first version was wrong.

    Trust follows the `by` host — the MTA that WROTE the header — not the
    `from` host it received from. At seq 2 our own relay wrote
    "from evil-vps.example [203.0.113.7]", and that is a TRUE observation:
    our machine really did accept a connection from that address. The
    boundary is therefore 2, not 1.

    Getting this backwards discards the single most valuable line in the
    chain — the attacker's real originating IP as seen by equipment we
    control — while keeping seq 3, which the attacker's own box wrote and
    which is fiction.
    """
    hops = parse_received_chain(CHAIN, trusted=("corp.example",))
    assert [h.seq for h in hops if h.is_trusted_boundary] == [2]
    assert hops[2].by_host == "relay.corp.example"      # ours: it observed
    assert hops[3].by_host == "evil-vps.example"        # theirs: it claimed


def test_with_no_configured_mtas_only_the_first_hop_is_trusted():
    """The conservative answer, and the only defensible one when the
    platform has not been told which MTAs belong to the recipient. A
    default of "trust the whole chain" would believe forged hops."""
    hops = parse_received_chain(CHAIN, trusted=())
    assert [h.seq for h in hops if h.is_trusted_boundary] == [0]


def test_infrastructure_is_never_proposed_from_above_the_boundary():
    """198.51.100.1 exists only because the attacker typed it into a
    header their own box wrote. A selector minted from it attributes the
    mail to an address of the sender's choosing.

    203.0.113.7 is the opposite case and must be KEPT: our own relay
    wrote that line, so it is our observation of who actually connected.
    It is the most valuable identifier in the message, and a boundary
    rule that discarded it would be safe and useless.
    """
    parsed = ParsedEmail()
    parsed.hops = parse_received_chain(CHAIN, trusted=("corp.example",))
    ips = {c["value"] for c in selector_candidates_for_email(parsed)
           if c["selector_type"] in ("IPV4", "IPV6")}
    assert ips == {"10.0.0.5", "10.0.0.9", "203.0.113.7"}
    assert "198.51.100.1" not in ips


def test_an_empty_chain_is_not_a_crash():
    assert parse_received_chain([], trusted=("corp.example",)) == []


# --- invariant 9: the displayed identifier is the spoofed one ------------

def test_invariant_9_a_presented_caller_id_never_becomes_a_selector():
    """THE fund-losing bug of this subsystem, prevented in the one
    function that decides what becomes a selector.

    Caller ID spoofing is the vishing technique. Minting a strong PHONE
    selector from the number the victim's handset showed puts a real
    subscriber's number on a criminal actor's node — attributing a crime
    to whoever the attacker picked out of the air.
    """
    call = {
        "presented_number_e164": "+441234567890",   # spoofed: the victim's bank
        "presented_name": "HSBC Fraud Team",
        "p_asserted_identity": "sip:2049@trunk-42.carrier.example",
        "called_number_e164": "+447700900123",
        "originating_trunk": "trunk-42",
    }
    values = {c["value"] for c in selector_candidates_for_call(call)}
    assert "+441234567890" not in values
    assert "sip:2049@trunk-42.carrier.example" in values
    assert "+447700900123" in values


def test_a_verified_attestation_a_promotes_the_presented_number_only_to_weak():
    """The one case where the carrier has vouched for the number — and
    even then it says "this caller may use it", not "this caller is its
    subscriber", so it is offered weak."""
    call = {
        "presented_number_e164": "+441234567890",
        "stir_shaken_attestation": "A",
        "stir_shaken_verified": True,
    }
    got = [c for c in selector_candidates_for_call(call)
           if c["value"] == "+441234567890"]
    assert len(got) == 1
    assert got[0]["strength"] == "weak"


def test_an_unverified_attestation_claim_promotes_nothing():
    """`stir_shaken_attestation` without `stir_shaken_verified` is a claim
    that nobody checked. One boolean fewer and it would read as verified."""
    call = {"presented_number_e164": "+441234567890",
            "stir_shaken_attestation": "A", "stir_shaken_verified": False}
    assert selector_candidates_for_call(call) == []


# --- BEC header forensics ------------------------------------------------

BEC = b"""\
Received: from mx-edge.corp.example (mx-edge.corp.example [10.0.0.5]) by mail.corp.example with ESMTPS id abc; Mon, 20 Jul 2026 09:00:03 +0000
Received: from evil-vps.example (evil-vps.example [203.0.113.7]) by mx-edge.corp.example with ESMTP id ghi; Mon, 20 Jul 2026 09:00:01 +0000
Authentication-Results: mail.corp.example; spf=fail smtp.mailfrom=evil-vps.example; dkim=fail header.d=acme-holdings.example; dmarc=fail
Message-ID: <kit-20260720-0001@evil-vps.example>
From: "Jane Okafor, CFO" <jane.okafor@acme-holdings.example>
Reply-To: jane.okafor.acme@gmail.com
Return-Path: <bounce@evil-vps.example>
To: finance@acme-holdings.example
Subject: Updated remittance details - urgent
Date: Mon, 20 Jul 2026 09:00:00 +0000
Content-Type: text/plain; charset=utf-8

Please update the account for the Q3 payment to https://acme-payments.example/verify
before close of business.
"""


def test_from_and_reply_to_divergence_is_the_bec_finding():
    parsed = parse_eml(BEC, trusted=("corp.example",))
    assert parsed.header_from == "jane.okafor@acme-holdings.example"
    assert parsed.header_from_display == "Jane Okafor, CFO"
    assert parsed.header_reply_to == "jane.okafor.acme@gmail.com"
    assert parsed.from_replyto_divergent is True
    assert parsed.reply_to_is_freemail is True


def test_divergence_is_compared_on_the_domain_not_the_address():
    """BEC uses ceo@company.com -> ceo.company@gmail.com. An
    address-equality test would call that convergent and miss every real
    case."""
    same = ParsedEmail(header_from="a@x.example", header_reply_to="b@x.example")
    assert same.from_replyto_divergent is False
    diff = ParsedEmail(header_from="a@x.example", header_reply_to="a@y.example")
    assert diff.from_replyto_divergent is True


def test_a_failing_dkim_domain_is_never_recorded_as_an_identity():
    """`header.d=acme-holdings.example` on a FAILING signature is a claim
    by the attacker. Recording it would invite every downstream reader —
    and every report — to treat a forgery as authenticated. The DB has a
    CHECK saying the same thing."""
    parsed = parse_eml(BEC, trusted=("corp.example",))
    assert parsed.dkim_result == "FAIL"
    assert parsed.dkim_domain is None
    assert parsed.spf_domain is None
    domains = {c["value"] for c in selector_candidates_for_email(parsed)
               if c["selector_type"] == "DOMAIN"}
    assert domains == set()


def test_a_passing_dkim_domain_is_the_one_durable_sender_identity():
    good = BEC.replace(b"dkim=fail header.d=acme-holdings.example",
                       b"dkim=pass header.d=acme-holdings.example")
    parsed = parse_eml(good, trusted=("corp.example",))
    assert parsed.dkim_result == "PASS"
    assert parsed.dkim_domain == "acme-holdings.example"
    durable = [c for c in selector_candidates_for_email(parsed)
               if c["strength"] == "durable" and c["selector_type"] == "DOMAIN"]
    assert durable and durable[0]["value"] == "acme-holdings.example"


def test_a_domain_is_scoped_to_the_method_that_passed():
    """`spf=pass smtp.mailfrom=a.example; dkim=fail header.d=b.example`
    must not attribute b.example to SPF. Splitting on ';' is what keeps
    the clauses apart."""
    raw = BEC.replace(
        b"spf=fail smtp.mailfrom=evil-vps.example; "
        b"dkim=fail header.d=acme-holdings.example",
        b"spf=pass smtp.mailfrom=sender.example; "
        b"dkim=fail header.d=acme-holdings.example")
    parsed = parse_eml(raw, trusted=("corp.example",))
    assert parsed.spf_domain == "sender.example"
    assert parsed.dkim_domain is None


def test_from_is_offered_weak_and_never_strong():
    """The field BEC forges. It is worth proposing — it is what the
    victim saw — but never as an authenticated identity."""
    parsed = parse_eml(BEC, trusted=("corp.example",))
    froms = [c for c in selector_candidates_for_email(parsed)
             if c["value"] == "jane.okafor@acme-holdings.example"]
    assert froms and all(c["strength"] == "weak" for c in froms)


def test_the_html_body_is_recorded_as_present_and_never_extracted_as_markup():
    """Rendering an HTML body fires the actor's tracking pixel from the
    investigator's IP (docs/19 §5). The markup stays in the exhibit."""
    html = BEC.replace(b"Content-Type: text/plain; charset=utf-8",
                       b"Content-Type: text/html; charset=utf-8")
    parsed = parse_eml(html, trusted=("corp.example",))
    assert parsed.has_html_body is True
    assert not parsed.body_text
    assert any(g["step"] == "body_text" for g in parsed.gaps)


def test_urls_are_extracted_for_pivoting():
    parsed = parse_eml(BEC, trusted=("corp.example",))
    assert "https://acme-payments.example/verify" in parsed.extracted_urls


# --- invariant 12: nothing is silently dropped ---------------------------

def test_invariant_12_a_missing_auth_results_header_is_a_recorded_absence():
    """A NULL dkim_result reads as "DKIM did not pass". A recorded gap
    reads as "nobody checked". Those are different findings."""
    bare = b"From: a@b.example\r\nSubject: x\r\n\r\nbody\r\n"
    parsed = parse_eml(bare)
    assert parsed.dkim_result is None
    steps = {g["step"] for g in parsed.gaps}
    assert "authentication_results" in steps
    assert "received_chain" in steps


def test_invariant_12_an_unparseable_message_still_yields_a_record():
    """A BEC exhibit is attacker-authored by definition. "The parser
    crashed" is not an acceptable answer to "what does this mail say"."""
    for junk in (b"", b"\x00\x01\x02\xff\xfe", b"Subject" + b"A" * 5000):
        parsed = parse_eml(junk)
        assert isinstance(parsed, ParsedEmail)


def test_a_header_containing_a_newline_cannot_forge_a_second_field():
    """RFC 2047 decoding can yield embedded CR/LF. A report or log that
    prints headers one per line would otherwise show attacker-authored
    fields as if the MTA had written them."""
    sneaky = (b"From: =?utf-8?b?" +
              __import__("base64").b64encode("a\r\nX-Admin: yes".encode()) +
              b"?= <a@b.example>\r\nSubject: x\r\n\r\nbody\r\n")
    parsed = parse_eml(sneaky)
    for value in (parsed.header_from_display or "", parsed.subject or ""):
        assert "\r" not in value and "\n" not in value


# --- defanging -----------------------------------------------------------

def test_urls_are_defanged_in_the_authority_only():
    assert defang("https://evil.com/a.b.c") == "hxxps://evil[.]com/a.b.c"
    assert defang("http://x.y.example") == "hxxp://x[.]y[.]example"


def test_defanging_a_bare_domain_still_breaks_it():
    assert defang("evil.com") == "evil[.]com"


def test_defanging_is_safe_on_empty_and_odd_input():
    assert defang("") == ""
    assert "javascript" in defang("javascript:alert(1)")


# ---------------------------------------------------------------------------
# The ninth adversarial pass, 2026-07-26. Each of these fails without its fix.
# ---------------------------------------------------------------------------

def test_an_appended_authentication_results_header_does_not_win():
    """THE forged-verdict defect of this subsystem.

    An MTA PREPENDS, so index 0 is the receiving organisation's own
    verdict and anything the sender wrote is LAST. Reading last-wins let
    an attacker append their own `dkim=pass header.d=microsoft.com` and
    have it override the real `dkim=fail` -- producing microsoft.com as a
    DURABLE, "cryptographically authenticated" DOMAIN selector.

    This module gets the direction right for `Received` and got it exactly
    backwards here. Same shape as the Phase 7 forged-PGP verdict: the DB
    CHECK could not help, because the parser made the result and the
    domain agree on the forged value.
    """
    evil = (
        b"Received: from evil.example ([203.0.113.9]) by mx.corp.example;"
        b" Mon, 20 Jul 2026 09:00:00 +0000\r\n"
        b"Authentication-Results: mx.corp.example; spf=fail"
        b" smtp.mailfrom=evil.example; dkim=fail header.d=evil.example;"
        b" dmarc=fail\r\n"
        b"Authentication-Results: mx.corp.example; spf=pass"
        b" smtp.mailfrom=microsoft.com; dkim=pass header.d=microsoft.com;"
        b" dmarc=pass\r\n"
        b"From: a@evil.example\r\nSubject: x\r\n\r\nbody\r\n")
    parsed = parse_eml(evil, trusted=("corp.example",))
    assert parsed.dkim_result == "FAIL"
    assert parsed.dkim_domain is None
    assert parsed.spf_domain is None
    domains = {c["value"] for c in selector_candidates_for_email(parsed)
               if c["selector_type"] == "DOMAIN"}
    assert "microsoft.com" not in domains
    # And the extra header is itself a finding, not something to discard.
    assert any("Authentication-Results headers" in g.get("reason", "")
               for g in parsed.gaps)


def test_a_pass_then_fail_signature_pair_is_ordinary_mail_not_a_500():
    """A mailing list or forwarder re-signs, so `dkim=pass ...; dkim=fail
    ...` is routine. Reading the result last-wins and the domain
    first-pass produced FAIL + a domain, which violates
    `email_dkim_domain_needs_pass` -- surfacing as a CheckViolation 500
    AFTER the WORM exhibit had already committed, leaving an object-locked
    exhibit with nothing describing it."""
    raw = (b"Authentication-Results: mx.corp.example;"
           b" dkim=pass header.d=acme.example;"
           b" dkim=fail header.d=list.example\r\n"
           b"From: a@acme.example\r\nSubject: x\r\n\r\nbody\r\n")
    parsed = parse_eml(raw)
    assert parsed.dkim_result == "PASS"
    assert parsed.dkim_domain == "acme.example"
    # The invariant the DB constraint expresses, asserted here too.
    assert not (parsed.dkim_domain and parsed.dkim_result != "PASS")


def test_a_failing_method_never_carries_a_domain_even_alone():
    raw = (b"Authentication-Results: mx.corp.example;"
           b" dkim=fail header.d=spoofed.example\r\n"
           b"From: a@b.example\r\nSubject: x\r\n\r\nbody\r\n")
    parsed = parse_eml(raw)
    assert parsed.dkim_result == "FAIL"
    assert parsed.dkim_domain is None


def test_no_infrastructure_is_proposed_when_no_trusted_mtas_are_configured():
    """Unconfigured means unknown, and the honest output for unknown is
    nothing.

    With no NOCTORNAL_TRUSTED_MTA_HOSTS the boundary defaults to seq 0 --
    correct for what to EXCLUDE, and silently inverted for what to
    include: hop 0 is the RECIPIENT'S OWN server, so this was offering the
    victim's internal relay address as durable actor infrastructure while
    suppressing the attacker's real sending IP one hop above it.
    """
    chain = [
        "from mail-internal.corp.local ([10.1.2.3]) by exchange.corp.local;"
        " Mon, 20 Jul 2026 09:00:02 +0000",
        "from evil.example ([203.0.113.9]) by mx.corp.local;"
        " Mon, 20 Jul 2026 09:00:01 +0000",
    ]
    parsed = ParsedEmail()
    parsed.hops = parse_received_chain(chain, trusted=())
    ips = {c["value"] for c in selector_candidates_for_email(parsed)
           if c["selector_type"] in ("IPV4", "IPV6")}
    assert ips == set(), "the victim's own relay must not be proposed"
    # Configured, the same chain does yield the observation.
    parsed.hops = parse_received_chain(chain, trusted=("corp.local",))
    ips = {c["value"] for c in selector_candidates_for_email(parsed)
           if c["selector_type"] in ("IPV4", "IPV6")}
    assert "203.0.113.9" in ips


def test_defang_breaks_a_host_that_carries_no_scheme():
    """`split("/", 3)` puts the authority at index 2 only when a
    `scheme://` occupied 0 and 1. Without one, index 2 is a PATH segment,
    so the authority was never bracketed and -- no scheme having matched
    either -- the string came back untouched. A live host, out of the
    helper whose whole job is that it is not one.

    Not exotic: requested_url and final_url are free text and a victim
    report routinely omits the scheme."""
    assert defang("paypal-secure.example/login/x") == "paypal-secure[.]example/login/x"
    assert defang("www.evil.example/a/b") == "www[.]evil[.]example/a/b"
    assert defang("evil.example") == "evil[.]example"
    # The scheme-carrying forms still behave.
    assert defang("https://evil.example/x") == "hxxps://evil[.]example/x"
    assert defang("http://a.b.example") == "hxxp://a[.]b[.]example"
