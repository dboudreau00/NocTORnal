"""Seed the Deception pane: a phishing capture, a BEC message, a vishing call.

docs/19. Development only. Every value here is fiction, and each row is
chosen to make ONE of the subsystem's rules visible on screen rather than
just present in the schema:

- the **capture** has a three-hop redirect chain (shortener → compromised
  host → kit) and a TLS SPKI hash, so the pane can show that the evidence
  is the whole fetch and not the screenshot;
- the **BEC message** has `From` ≠ `Reply-To` with a free-mail reply, a
  FAILING DKIM whose claimed domain is therefore NOT recorded, and a
  Received chain whose trust boundary sits one hop below a forged
  originating IP;
- the **call** has a spoofed presented CLI next to a real trunk and an
  unverified attestation, so the presented-vs-durable split is visible.

    .venv\\Scripts\\python scripts\\seed_deception_demo.py --case OP-SHOWCASE-26

Run it twice and it does nothing the second time.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "apps" / "api" / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "ontology" / "src"))

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


from _env import load_env_local  # noqa: E402

load_env_local()

BEC_EML = b"""\
Received: from mx-edge.latticework-holdings.example (mx-edge.latticework-holdings.example [10.4.0.9]) by mail.latticework-holdings.example with ESMTPS id 7f2a; Fri, 17 Jul 2026 08:14:31 +0000
Received: from relay.latticework-holdings.example (relay.latticework-holdings.example [10.4.0.3]) by mx-edge.latticework-holdings.example with ESMTP id 7f29; Fri, 17 Jul 2026 08:14:30 +0000
Received: from vps-4471.hostmarket.example (vps-4471.hostmarket.example [203.0.113.44]) by relay.latticework-holdings.example with ESMTP id 7f28; Fri, 17 Jul 2026 08:14:28 +0000
Received: from mail.microsoft.example ([198.51.100.20]) by vps-4471.hostmarket.example; Fri, 17 Jul 2026 08:14:00 +0000
Authentication-Results: mail.latticework-holdings.example; spf=fail smtp.mailfrom=vps-4471.hostmarket.example; dkim=fail header.d=latticework-holdings.example; dmarc=fail
Message-ID: <20260717081400.7f28.kitbuild@vps-4471.hostmarket.example>
From: "Moira Vance, Group CFO" <m.vance@latticework-holdings.example>
Reply-To: m.vance.latticework@gmail.com
Return-Path: <bounce-7f28@vps-4471.hostmarket.example>
To: accounts.payable@latticework-holdings.example
Cc: treasury@latticework-holdings.example
Subject: Updated remittance details - Sandhurst invoice, please action today
Date: Fri, 17 Jul 2026 08:14:00 +0000
Content-Type: text/plain; charset=utf-8

Hi,

The Sandhurst payment due today needs to go to our new account -- the old
one is frozen pending the audit. Details are on the portal:

  https://latticework-portal.secure-billing.example/verify?ref=7f28

I am in back-to-back meetings so please do not call; confirm here by email
once it is away.

Moira
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", default="OP-SHOWCASE-26",
                        help="case CODE to seed into")
    args = parser.parse_args()

    from noctornal_api.db import connect
    from noctornal_api.deception import DeceptionService, parse_eml
    from noctornal_api.evidence import EvidenceService, EvidenceStorage

    conn = connect()
    # The case's own label is fetched because the exhibit must carry AT
    # LEAST it. `core.enforce_tlp_floor()` fires on core.evidence and
    # refuses anything below the case floor -- an element is protected by
    # both its own label and its case's, and a CLEAR exhibit inside an
    # AMBER case would be a hole in that.
    #
    # R23 (2026-07-26): this script asked for a hardcoded CLEAR, so the
    # BEC exhibit was refused on EVERY machine -- demo-case and
    # demo-network both create their cases at AMBER. The Deception pane
    # therefore showed a capture and a call but never the e-mail, which is
    # the row carrying the Received-chain and DKIM reasoning the pane
    # exists to demonstrate. Reading the floor rather than guessing it
    # also makes --case work against a RED case.
    row = conn.execute(
        'SELECT id, owner_user_id, classification FROM core."case" '
        'WHERE code = %s',
        (args.case,)).fetchone()
    if row is None:
        print(f"no case {args.case!r}; run bootstrap.py demo-network first",
              file=sys.stderr)
        return 1
    case_id, owner, floor = row

    svc = DeceptionService(conn)
    if svc.captures(case_id, clearance="RED"):
        print(f"{args.case} already has deception rows; nothing to do")
        conn.close()
        return 0

    # -- 1. the phishing capture -----------------------------------------
    capture_id = svc.record_capture(
        case_id=case_id,
        requested_url="https://lattice-invoice.example/r/7f28",
        final_url="https://latticework-portal.secure-billing.example/verify",
        capture_method="VICTIM_SUPPLIED",
        captured_by=owner,
        classification="CLEAR",
        capture_tool="analyst screenshot from the reporting user",
        http_status=200,
        is_live=True,
        page_title="Latticework Holdings - Supplier Portal Sign-in",
        favicon_hash="-1274384433",
        tls={
            "subject": "CN=secure-billing.example",
            "issuer": "CN=R3, O=Let's Encrypt, C=US",
            "not_before": datetime(2026, 7, 12, tzinfo=timezone.utc),
            "not_after": datetime(2026, 10, 10, tzinfo=timezone.utc),
            # The durable web identifier: survives the domain rotation
            # this kit will do next week.
            "spki_sha256": bytes.fromhex(
                "9f2c41ab7d5e0c8831b6a4f209de77c3"
                "5b48e91072aa6fd4381c05e7b9a2364d"),
        },
        note="Reported by accounts.payable after the BEC message below. "
             "The victim had already entered credentials; a password reset "
             "was forced before this capture was recorded.",
        hops=[
            {"url": "https://lattice-invoice.example/r/7f28",
             "hop_kind": "REQUESTED", "http_status": 302,
             "resolved_ip": "203.0.113.90", "asn": 64496,
             "server_header": "nginx"},
            {"url": "https://cdn.brightsails-charity.example/assets/go.php",
             "hop_kind": "HTTP_30X", "http_status": 302,
             "resolved_ip": "198.51.100.77", "asn": 64497,
             "server_header": "Apache/2.4.52"},
            {"url": "https://latticework-portal.secure-billing.example/verify",
             "hop_kind": "HTTP_30X", "http_status": 200,
             "resolved_ip": "203.0.113.44", "asn": 64496,
             "server_header": "nginx"},
        ],
    )

    # -- 2. the BEC message ----------------------------------------------
    # The exhibit lands FIRST and the parse is derived from it.
    try:
        exhibit = EvidenceService(conn, EvidenceStorage()).ingest(
            case_id=case_id,
            title="remittance-change.eml",
            media_type="message/rfc822",
            data=BEC_EML,
            acquired_by=owner,
            acquisition_method="MANUAL_UPLOAD",
            classification=floor,
            is_hostile_markup=True,
        )
        evidence_id = exhibit.evidence_id
    except Exception as exc:                                  # noqa: BLE001
        # PRINT THE ACTUAL ERROR. This handler used to report "evidence
        # store unavailable" for anything at all, and the thing it was
        # actually catching was a Postgres policy refusal -- so it sent
        # whoever ran it to look at MinIO, which was working perfectly.
        # A diagnostic that names the wrong subsystem is worse than none.
        print(f"could not store the BEC exhibit, skipping the e-mail row:\n"
              f"  {type(exc).__name__}: {exc}", file=sys.stderr)
        evidence_id = None

    if evidence_id is not None:
        parsed = parse_eml(BEC_EML, trusted=("latticework-holdings.example",))
        svc.record_email(
            case_id=case_id, evidence_id=evidence_id, parsed=parsed,
            recorded_by=owner, classification="CLEAR",
            display_name_impersonates="Latticework Holdings (Group CFO)",
        )

    # -- 3. the vishing call ---------------------------------------------
    svc.record_call(
        case_id=case_id,
        started_at=datetime(2026, 7, 17, 9, 2, tzinfo=timezone.utc),
        ended_at=datetime(2026, 7, 17, 9, 8, 40, tzinfo=timezone.utc),
        direction="INBOUND_TO_VICTIM",
        record_source="CARRIER_CDR",
        recorded_by=owner,
        classification="CLEAR",
        # What the victim's handset showed. The bank's real published
        # number, spoofed. This never becomes a selector.
        presented_number="+44 20 7946 0018",
        presented_number_e164="+442079460018",
        presented_name="LATTICEWORK BANK",
        # What the network saw.
        originating_trunk="SIP/hostmarket-eu-04",
        p_asserted_identity="sip:44471@trunk-04.hostmarket.example",
        carrier_name="Hostmarket Telecom BV",
        stir_shaken_attestation="C",
        stir_shaken_verified=False,
        called_number_e164="+442071838750",
        duration_seconds=400,
        disposition="ANSWERED",
        sip_call_id="7f28-9c2a-4471@trunk-04.hostmarket.example",
        sip_from_uri="sip:44471@trunk-04.hostmarket.example",
        source_ip="203.0.113.44",
        note="Caller claimed to be the bank's fraud team confirming the "
             "remittance change. The presented number matches the bank's "
             "published line and was spoofed; attestation C means the "
             "originating carrier vouches for nothing.",
    )
    conn.commit()

    print(f"seeded {args.case}:")
    print(f"  capture   {capture_id}  (3 redirect hops, TLS SPKI recorded)")
    print("  email     From != Reply-To, free-mail reply, DKIM FAIL")
    print("  call      presented CLI spoofed, attestation C unverified")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
