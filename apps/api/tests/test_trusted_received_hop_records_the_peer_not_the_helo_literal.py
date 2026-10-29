"""A trusted Received hop records the address that connected, not the one
the sender typed into EHLO.

Postfix writes `from [helo literal] (rdns [peer])`, qmail writes
`from host (HELO [literal]) (peer)` and Exim writes `from [peer]
(helo=[literal])`. Only the peer is an observation by infrastructure the
recipient controls; the EHLO literal is the sender's choice, and an address
after `by` is the receiving MTA. Recording either as the hop's address would
attribute the sender to an address they picked, graded durable.

Pure: no database.
"""
from __future__ import annotations

from noctornal_api.deception import (
    ParsedEmail,
    _sending_host,
    parse_received_chain,
    proposal_candidates,
    selector_candidates_for_email,
)

_TOP = ("from mx.corp.example (mx.corp.example [10.0.0.5]) "
        "by mail.corp.example with ESMTPS id aaa; Mon, 20 Jul 2026 09:00:02 +0000")


def _boundary(line: str):
    hops = parse_received_chain([_TOP, line], trusted=("corp.example",))
    boundary = next(h for h in hops if h.is_trusted_boundary)
    assert boundary.seq == 1
    return hops, boundary


def test_a_postfix_hop_with_a_helo_literal_records_the_peer():
    hops, boundary = _boundary(
        "from [198.51.100.99] (unknown [203.0.113.50]) "
        "by mx.corp.example (mx.corp.example [192.0.2.10]) "
        "with ESMTPS id bbb; Mon, 20 Jul 2026 09:00:01 +0000")
    assert boundary.from_ip == "203.0.113.50"

    parsed = ParsedEmail()
    parsed.hops = hops
    offered = {c["value"] for c in selector_candidates_for_email(parsed)
               if c["selector_type"] in ("IPV4", "IPV6")}
    assert "203.0.113.50" in offered
    assert "198.51.100.99" not in offered
    assert "192.0.2.10" not in offered

    host = _sending_host((boundary.seq, boundary.from_host, boundary.from_ip,
                          boundary.by_host, boundary.received_at,
                          boundary.is_trusted_boundary))
    assert host["boundary_confirmed"] is True
    assert host["ip"] == "203.0.113.50"
    proposed = [c["label"] for c in proposal_candidates(
        "email", {"sending_host": host, "extracted_urls": []})
        if c["selector_type"] in ("IPV4", "IPV6")]
    assert proposed == ["203.0.113.50"]


def test_an_exim_hop_does_not_take_the_helo_literal():
    _hops, boundary = _boundary(
        "from [203.0.113.50] (port=40123 helo=[198.51.100.99]) "
        "by mx.corp.example with esmtps (Exim 4.97) id bbb; "
        "Mon, 20 Jul 2026 09:00:01 +0000")
    assert boundary.from_ip == "203.0.113.50"


def test_a_qmail_hop_does_not_take_the_helo_literal():
    _hops, boundary = _boundary(
        "from unknown (HELO [198.51.100.99]) (203.0.113.50) "
        "by mx.corp.example with SMTP; Mon, 20 Jul 2026 09:00:01 +0000")
    assert boundary.from_ip == "203.0.113.50"


def test_an_address_after_by_is_not_the_connecting_address():
    _hops, boundary = _boundary(
        "from sender.example by mx.corp.example (mx.corp.example [192.0.2.10]) "
        "with ESMTP id ccc; Mon, 20 Jul 2026 09:00:01 +0000")
    assert boundary.from_ip is None
