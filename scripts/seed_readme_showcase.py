"""Seed the README showcase case with what its screenshots claim. Development only.

    .venv\\Scripts\\python scripts\\seed_readme_showcase.py --case OP-SHOWCASE-26 --owner-email you@example.org

Run it AFTER `bootstrap.py demo-network` and the other seeders
(seed_deception_demo, seed_lab_demo, seed_feeds_demo, seed_ach_demo), on
the case the README's screenshots are taken from.

## Why this exists

README screenshot review, 2026-09-23. Round 1 shot every pane of
OP-SHOWCASE-26 and found the estate too thin for the paragraphs under the
images: the hero sociogram printed "0 of 37 elements rest on an exhibit" in
red directly under the tagline "every line of it traces back to an
exhibit"; no tie was inferred, so nothing was drawn dashed; every entity was
a persona; no selector existed, so search could not show a hit reached
through one; nothing sat above CLEAR, so the report's redaction was never
seen working; triage, the inbox and the comms pane were empty; the
analytics trend was a single dot; and the custody log held one ACQUIRED
row under a paragraph about recording every read. This writes the missing
material, each piece through the service the console itself would use.

## Everything goes through the services

Graph elements through `GraphWriteService` (each with its assertion in the
same transaction), exhibits through `EvidenceService` into the dev MinIO,
selectors through `SelectorStore` and its normalisers, bindings and the
contact block through the comms services, proposals through
`CaptureService` / `ProposalStore` / `ProposalReview`, notifications through
the platform's own producers (`notify_events`, `ApprovalService`,
`BreakGlassService`), runs through `AnalyticsRunService`. A seeder that
INSERTs graph rows directly creates exactly the unfounded graph the model
exists to prevent, and it is the first thing a reader copies. The SQL
writes that remain are the ones `bootstrap.py create-user` makes for an
account (clearance and global roles have no service) and the two audit
rows the console's routes write beside their service calls: the capture
route's DOCUMENT_CAPTURED and the edge correction route's EDGE_UPDATED.

## The analytics story is not moved

The README's analytics paragraph rests on demo-network's shape: oriel is the
sole bridge to the bitwright crew, and dvina and kolar redundantly bridge
halcyon and meridian. The console draws the sociogram and computes the
Analysis pane over ONE projection (`state.proj` in app.js: All ties,
inferred IN, LOW), so anything drawn there is also counted there. So:

- The new GROUP, WALLET and INFRA entities hang off STRUCTURAL edge types
  (CONTROLS, USED), which the ontology marks `is_social_tie = false`. The
  "All ties" projection keeps those edges out, so no path between two
  identities changes.
- The one inferred tie sits INSIDE the bitwright crew, parallel to the
  bit_forge / bit_lathe vouch, so no dyad is added, and the analyst then
  corrects its weight to 0 (the correction route's own path, with its
  reason). `analytics.materialise` collapses parallel ties into one dyad
  whose strength is the SUM of their weights, so a zero-weight parallel
  leaves the igraph graph, and every number computed from it, exactly as
  it was. At weight 1 (what an accepted proposal is given) it did not.
  Measured beside each of the sixteen ties inside a crew: on the thirteen
  whose dyad carries a positive tie it moved eigenvector values for 13 or
  14 of the fifteen, on the three purely hostile dyads it made the dyad
  contested and moved the balance count, and at this pair it inverted the
  eigenvector ranking (bit_forge went from 12th to 1st, hal_vector from
  1st to 7th) and moved constraint, effective size, hierarchy and harmonic
  closeness (README screenshot review, 2026-09-23, verifier round; the
  first version of this docstring called that "shift slightly", which it
  was not). The canvas draws width by weight over the projection's own
  range, so the inferred tie draws at the thinnest width, dashed, beside
  the vouch: suggested, and weighed at nothing until its content is seen.

What still moves, stated rather than discovered, and held exactly by
`apps/api/tests/test_seed_readme_showcase_pg.py`:

- With inferred ties counted, bit_forge's positive out-degree and
  bit_lathe's positive in-degree (the Analysis table's given and received
  columns) rise by one, and so does both endpoints' positive degree in the
  inspector. Every social edge type carries a sign (the ontology has no
  social type at sign 0), and those columns count ties, not strength, so an
  inferred tie the default projection draws cannot avoid them.
- The five new entities are isolates in the social projection, so the
  figures computed over the whole population move: every percentile,
  harmonic closeness (normalised by n - 1, so every value scales by 14/19
  and no rank changes), density, the community and component counts, the
  key-player fragmentation figures, and the Analysis pane's mode warning,
  which names the non-actor isolates and says exactly this. No rank, no
  raw structural value, no key-player or top-3 set, no cut vertex, bridge,
  balance count or community of the fifteen changes.

## What is NOT here, and why

- `core.node.first_seen` exists and no service writes it
  (`GraphWriteService.create_node` takes no first seen), so the entity
  list's First seen column stays "not recorded". An UPDATE would be a graph
  write around the service.
- No exhibit is past its retention deadline. `RetentionService.due()` dates
  an exhibit by its CASE's `retention_until`, and ingest and document clocks
  are stamped now plus a positive rule, so the only way to put one exhibit
  on the due list is to expire the whole case, which puts every exhibit on
  it. The legal hold is applied; the due list stays empty.
- The break-glass grant is ended but NOT reviewed. The officer's review
  queue (`BreakGlassService.unreviewed`, the only list of grants the
  console has) shows only unreviewed grants, so a reviewed grant leaves the
  one place that shows it. A second grant made only to be reviewed would put
  a second URGENT notice in the owner's inbox for a second emergency the
  case has no reason for (it holds one GREEN item). It is left for the
  officer account to review on camera.
- Edge review state: every demo-network tie reads PROPOSED and no service
  moves `core.edge.review`, so every node keeps its unreviewed ring.

## Labels

Everything is TLP:CLEAR except ONE exhibit, `fraud-desk-liaison-note.txt`
at GREEN, left unlinked, so a report prepared at CLEAR withholds exactly
one exhibit and says so. The break-glass alert the officer receives is
GREEN by `BreakGlassService`'s own rule (it carries nothing about the case);
it is a notification, not case material.

## Safe to run twice

Every step first looks for what it would write and skips it if it is there,
so a second run doubles nothing and says which items were already present.
A step that writes several things that belong together (the inferred tie
and its correction; the capture, its audit row and the owner's notice; the
approval request; the break-glass grant, its read and its end) runs in one
transaction, so a run that dies half way leaves each step either done or
not started, and the next run finishes it.

**Every name, handle, wallet, host and person below is fiction.** Hosts are
reserved `.example` names; the wallet is a well formed bech32 address whose
program is a SHA-256 of a fixed sentence, so nobody holds its key; the Tox
key is the one the round 1 recipes already use; the Telegram id is the
placeholder the repository's own tests use.
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "apps" / "api" / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "ontology" / "src"))

from _env import load_env_local  # noqa: E402

load_env_local()

DEFAULT_CASE = "OP-SHOWCASE-26"
DEFAULT_COLLEAGUE = "colleague@example.org"
DEFAULT_OFFICER = "officer@example.org"
COLLEAGUE_NAME = "Demo Colleague"
OFFICER_NAME = "Demo Officer"

#: The exhibit seed_deception_demo writes. Its custody log gets the read and
#: the integrity check, and it carries the legal hold.
EML_TITLE = "remittance-change.eml"

#: The advert's Tox ID (nospam 5E1C0A7D, checksum 1B48), exactly as the
#: 04-triage and 08-comms recipes type it: the first 32 bytes are a SHA-256
#: of a fixed string, and the checksum is valid.
TOX_ADVERT = ("A350523A7935F37AF6DBD28F1FD984AD4D01E1FE2C45D36DC8FCFF4F1259FD11"
              "5E1C0A7D1B48")
#: The same public key under a ROTATED nospam (9C4E2B71, checksum F816). It
#: is what is stored as the binding, so correlating on the advert's ID
#: answers with a different tail and one identity: the nospam sentence of
#: the README, visible (08-comms designer, README screenshot review).
TOX_ROTATED = ("A350523A7935F37AF6DBD28F1FD984AD4D01E1FE2C45D36DC8FCFF4F1259FD11"
               "9C4E2B71F816")
#: The repository's own placeholder user id, already in its tests and docs,
#: so no new real-looking number enters a public README.
TELEGRAM_ID = "u:1234567890"
#: bech32 P2WPKH; witness program = SHA-256 of "NocTORnal README showcase:
#: meridian escrow wallet (fiction)", first 20 bytes. Well formed, and
#: nobody holds a key for it.
WALLET = "bc1qhcz8kccajfrz04fuwmxmxrf4exu7t3yc2sg4hg"
PORTAL = "secure-billing.example"

#: The advert's contact lines, byte for byte as a recipe would paste them:
#: the console shows a stored block only when the identical text is parsed
#: again ("Already parsed, showing the existing reading").
CONTACT_BLOCK = "\n".join([
    f"Tox: {TOX_ADVERT}",
    "Jabber: mer_kite@jabber.example",
    "Escrow: nm_escrow@jabber.example (forum escrow only)",
])
CONTACT_SOURCE = "http://nightmarket.example/t/8841"

#: The 21-line thread the 04-triage recipe pastes, so the queue it shows was
#: raised by the text it shows. No Telegram handle: a handle on a real
#: platform can be registered later and would inherit the advert.
TRIAGE_THREAD = "\n".join([
    "nightmarket.example / Access / [SELL] EU logistics RDP + VPN, thread 8841",
    "",
    "#1  mer_kite  (Vendor)",
    "Fresh RDP and VPN access, EU logistics sector.",
    "Three companies, 200 to 900 staff. Domain user on each,",
    "local admin on one. Samples on request, price in PM.",
    "Deals through forum escrow only.",
    "",
    "Contact:",
    f"Tox: {TOX_ADVERT}",
    "Jabber: mer_kite@jabber.example",
    "Escrow: nm_escrow@jabber.example (forum escrow only)",
    "",
    "#2  kolar  (Member)",
    "vouch. bought from him last month, access was as described.",
    "",
    "#3  mer_florin  (Member)",
    "+1 for kite. same escrow, no issues.",
    "",
    "#4  mer_kite  (Vendor)",
    "thanks kolar. everyone else, PM or Tox. no calls.",
])
TRIAGE_TITLE = "nightmarket thread 8841, mer_kite access advert"
TRIAGE_URL = "http://nightmarket.example/t/8841"
#: The extracted value parked as DISPUTED: the forum's escrow, which a
#: vendor's advert quotes and does not own.
DISPUTED_VALUE = "nm_escrow@jabber.example"
DISPUTED_NOTE = "escrow or vendor? check the stoplist before accepting"

#: The origin written on the one inferred tie. No extractor in the product
#: raises EDGE proposals yet, so the seeder stands in for one and says so
#: in the name rather than borrowing a component that does not exist. The
#: signal it describes is real and in the case: the conversation below.
INFERRED_ORIGIN = "showcase_seed/contact_graph"
INFERRED_RATIONALE = (
    "A one-to-one XMPP conversation between the handles bit_forge and "
    "bit_lathe on xmpp.bitwright.example: three messages in two weeks, from "
    "server metadata disclosed under DEMO/2026/0002-P1. Metadata only, no "
    "content read, so it says they talk, not what about.")
#: The analyst's reason for weighing the accepted suggestion at 0. True of
#: the case, and the reason the README's analytics survive it: a
#: zero-weight parallel adds no strength to the dyad it sits on.
INFERRED_WEIGHT_NOTE = (
    "Metadata only: three messages in two weeks say bit_forge and bit_lathe "
    "talk, not how close they are. Weighed at 0 until the content is seen, "
    "so the suggestion is on the chart and adds no strength to any figure.")


def _png(width: int = 96, height: int = 96, rgb=(58, 32, 64)) -> bytes:
    """A small valid PNG, one flat colour: a stand-in for a profile capture."""
    raw = b"".join(b"\x00" + bytes(rgb) * width for _ in range(height))

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return (struct.pack(">I", len(data)) + body
                + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


# Each post that backs a tie is written by the tie's SOURCE and names its
# target in the tie's own sense, and the link quotes it: the first version
# had "mer_kite: escrow through mer_ash" backing mer_kite ESCROW_FOR
# mer_ash, which says the opposite (ash holding the escrow), and "ash has
# held escrow for me" backing a VOUCH (README screenshot review,
# 2026-09-23, verifier round). The dates sit near demo-network's own dates
# for the same ties (it dates them months back from the build), so the
# timeline and the exhibit tell one story.
ESCROW_THREAD = f"""nightmarket.example / escrow board / thread 8790 (pinned)
[2024-11-18 21:14] mer_ledger: vouching for mer_kite, three clean deals with him
[2025-05-09 17:30] dvina: I vouch for mer_ledger, did the halcyon run with him
[2025-10-21 21:38] mer_ash: selling the EU access batch, escrow with mer_kite as usual, 5% fee
[2025-10-21 21:40] mer_kite: holding escrow for mer_ash. deposits to {WALLET} only
[2025-12-02 11:12] mer_ledger: vouch for mer_ash too, paid on time every time
[2026-05-19 08:02] mer_florin: mer_kite held my deposit nine days last time
[2026-05-19 09:15] mer_ledger: mer_florin is a scammer, ignore him
""".encode()

ROOM_EXPORT = b"""bitwright@conference.xmpp.bitwright.example, room history 2025-02-01 to 2026-05-14
[2025-02-20 19:02] bit_forge: bit_lathe is good for it, vouching
[2025-08-19 19:05] bit_lathe: bit_ember did the panel work, solid
[2025-08-19 19:06] bit_forge: +1 bit_ember, vouching
[2025-09-18 19:09] bit_lathe: vouching for bit_ember as well
[2026-02-23 10:40] bit_anvil: bit_lathe still owes me for the january job
[2026-02-23 10:44] bit_lathe: bit_anvil you got paid, take it to arbitration
"""

REGISTRAR = b"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >> endobj
trailer << /Root 1 0 R >>
%% Registrar response to request DEMO/2026/0002-R1 (fiction).
%% bit_forge is the contact handle on the reseller account that registered secure-billing.example on 2026-07-10.
%% The same account paid for the host behind latticework-portal.secure-billing.example.
%%EOF
"""

LIAISON = b"""Liaison note from the partner bank's fraud desk (fiction).
Shared at TLP:GREEN: the mule account named in remittance-change.eml
received two further transfers from other victims in July.
Not for onward release above GREEN.
"""

#: When the escrow wallet was first posted: the 2025-10-21 21:40 line of
#: thread 8790. The wallet's own dates and its CONTROLS ties take it, so the
#: entity is not dated before the post that shows it.
WALLET_SEEN = datetime(2025, 10, 21, 21, 40, tzinfo=timezone.utc)

#: (title, media type, bytes, acquisition, TLP, days before now, source url,
#:  description, entity labels it backs, ties it backs, relevance for the
#:  entity links). Each tie is (src, type, dst, quote): the quote is the
#:  passage that supports it, verbatim from the exhibit's text (or, for the
#:  image, its description), written by the source and naming the target
#:  in the tie's own sense. The link carries it as its relevance and the
#:  line it is on as its page reference, so the inspector says which line
#:  backs which tie. The four CLEAR exhibits back 12 of the 20 entities and
#:  11 of the 23 social ties: coverage lands near half, so the sociogram
#:  shows solid nodes beside hollow ones and beaded ties beside plain ones,
#:  which is the point of drawing the difference at all.
EXHIBITS = [
    ("meridian-escrow-thread-8790.txt", "text/plain", ESCROW_THREAD, "COLLECTOR",
     "CLEAR", 20, "http://nightmarket.example/t/8790",
     "Escrow board thread captured by the collector.",
     ["mer_ledger", "mer_kite", "mer_florin", "mer_ash", "dvina", WALLET],
     [("mer_ledger", "VOUCHED_FOR", "mer_kite",
       "mer_ledger: vouching for mer_kite"),
      ("mer_kite", "ESCROW_FOR", "mer_ash",
       "mer_kite: holding escrow for mer_ash"),
      ("mer_ledger", "ACCUSED_SCAM", "mer_florin",
       "mer_ledger: mer_florin is a scammer"),
      ("mer_ledger", "VOUCHED_FOR", "mer_ash",
       "mer_ledger: vouch for mer_ash too"),
      ("dvina", "VOUCHED_FOR", "mer_ledger",
       "dvina: I vouch for mer_ledger"),
      ("mer_kite", "CONTROLS", WALLET,
       f"mer_kite: holding escrow for mer_ash. deposits to {WALLET} only")],
     "Posts in escrow thread 8790 under this handle"),
    ("hal_vector-forum-profile.png", "image/png", _png(), "MANUAL_UPLOAD",
     "CLEAR", 14, "http://nightmarket.example/u/hal_vector",
     "Profile page of hal_vector, captured by hand. hal_vector's public "
     "vouch list names hal_prism, hal_quarry and hal_dune.",
     ["hal_vector", "hal_prism"],
     [("hal_vector", "VOUCHED_FOR", "hal_prism",
       "hal_vector's public vouch list names hal_prism"),
      ("hal_vector", "VOUCHED_FOR", "hal_quarry",
       "hal_vector's public vouch list names hal_prism, hal_quarry"),
      ("hal_vector", "VOUCHED_FOR", "hal_dune",
       "hal_vector's public vouch list names hal_prism, hal_quarry and hal_dune")],
     "On the profile page, as its owner or on its public vouch list"),
    ("bitwright-room-export.txt", "text/plain", ROOM_EXPORT, "COLLECTOR",
     "CLEAR", 11, None,
     "Export of the bitwright crew's XMPP room.",
     ["bit_lathe", "bit_ember"],
     [("bit_forge", "VOUCHED_FOR", "bit_lathe",
       "bit_forge: bit_lathe is good for it, vouching"),
      ("bit_forge", "VOUCHED_FOR", "bit_ember",
       "bit_forge: +1 bit_ember, vouching"),
      ("bit_lathe", "VOUCHED_FOR", "bit_ember",
       "bit_lathe: vouching for bit_ember as well")],
     "Posts in the crew's own room"),
    ("registrar-response-secure-billing.pdf", "application/pdf", REGISTRAR,
     "LEGAL", "CLEAR", 9, None,
     "Registrar response under request DEMO/2026/0002-R1.",
     ["bit_forge", PORTAL],
     [("bit_forge", "USED", PORTAL,
       "bit_forge is the contact handle on the reseller account that "
       "registered secure-billing.example")],
     "Named by the registrar's response"),
    # The ONE element above CLEAR, and unlinked: a report prepared at CLEAR
    # then shows "exhibits withheld 1" and the withheld statement, and
    # nothing on the graph changes colour because of it (README screenshot
    # review, 11-report).
    ("fraud-desk-liaison-note.txt", "text/plain", LIAISON, "MANUAL_UPLOAD",
     "GREEN", 5, None,
     "Liaison note from the partner bank's fraud desk.",
     [], [], None),
]
GREEN_TITLE = "fraud-desk-liaison-note.txt"

#: Other entity types, so the entity list's type filter has more than one
#: choice and the sociogram more than one colour. (type, label, attrs,
#: valid_from, assertion kwargs).
ENTITIES = [
    ("GROUP", "Halcyon crew", {"kind": "crew", "venue": "nightmarket"}, None,
     dict(basis="THIRD_PARTY_REPORT", reliability="B", credibility="2",
          confidence="MODERATE", external_ref="nightmarket threads 8611, 8790",
          rationale="Named as a crew in separate threads by its own members")),
    ("GROUP", "Meridian crew", {"kind": "crew", "venue": "nightmarket"}, None,
     dict(basis="THIRD_PARTY_REPORT", reliability="B", credibility="2",
          confidence="MODERATE", external_ref="nightmarket thread 8790",
          rationale="Named as a crew in separate threads by its own members")),
    ("GROUP", "Bitwright crew", {"kind": "crew", "venue": "xmpp"}, None,
     dict(basis="THIRD_PARTY_REPORT", reliability="B", credibility="2",
          confidence="MODERATE", external_ref="bitwright room export",
          rationale="The room it runs is named for it")),
    ("WALLET", WALLET, {"chain": "BTC", "role": "escrow deposit address"},
     WALLET_SEEN,
     dict(basis="DIRECT_OBSERVATION", reliability="A", credibility="1",
          confidence="HIGH", external_ref="nightmarket thread 8790")),
    ("INFRA", PORTAL, {"kind": "domain", "registered": "2026-07-10"},
     datetime(2026, 7, 10, tzinfo=timezone.utc),
     dict(basis="DIRECT_OBSERVATION", reliability="A", credibility="1",
          confidence="HIGH", external_ref="remittance-change.eml")),
]

#: Structural ties only: CONTROLS and USED are `is_social_tie = false`, so
#: none of these enters the default projection (see the module docstring).
STRUCTURAL = [
    ("CONTROLS", "Meridian crew", WALLET, WALLET_SEEN,
     dict(basis="ANALYST_INFERENCE", reliability="C", credibility="3",
          confidence="MODERATE",
          rationale="The crew's escrow runs through mer_kite, who gives this "
                    "address for deposits in thread 8790; read as the crew's "
                    "escrow wallet rather than his alone.")),
    ("CONTROLS", "mer_kite", WALLET, WALLET_SEEN,
     dict(basis="DIRECT_OBSERVATION", reliability="B", credibility="2",
          confidence="HIGH", external_ref="nightmarket thread 8790")),
    ("USED", "Bitwright crew", PORTAL, None,
     dict(basis="ANALYST_INFERENCE", reliability="C", credibility="3",
          confidence="LOW",
          rationale="The portal's reseller account belongs to bit_forge and "
                    "the kit's panel strings match the room export")),
    ("USED", "bit_forge", PORTAL, None,
     dict(basis="LEGAL_PROCESS", reliability="A", credibility="1",
          confidence="HIGH", external_ref="registrar response DEMO/2026/0002-R1")),
    ("USED", "Halcyon crew", PORTAL, None,
     dict(basis="ANALYST_INFERENCE", reliability="D", credibility="4",
          confidence="LOW",
          rationale="A halcyon recruiting post cites the portal as a "
                    "reference job; not corroborated")),
]

#: (selector type, raw value as observed, owner label, when: months back or
#: a date). Five
#: personas and the wallet. The two Jabber ids share the crew's private
#: server, so a search for "meridian" reaches dvina, whose name and
#: attributes do not contain it, THROUGH a selector, and says which.
SELECTORS = [
    ("JABBER", "ledger@xmpp.meridian.example", "mer_ledger", 7),
    ("JABBER", "dvina@xmpp.meridian.example/desk", "dvina", 6),
    ("TOX_PK", TOX_ADVERT, "mer_kite", 3),
    ("TELEGRAM_ID", TELEGRAM_ID, "oriel", 5),
    ("EMAIL", "vector@halcyon-mail.example", "hal_vector", 8),
    ("BTC_ADDR", WALLET, WALLET, WALLET_SEEN),
]

APPROVAL_JUSTIFICATION = (
    "mer_kite and mer_ash have only ever escrowed for each other, both went "
    "quiet the same week, and thread 8790 has them posting two minutes apart. "
    "Asking to fold mer_ash into mer_kite as one operator; this needs a "
    "second signature before anything moves.")
APPROVAL_REASON = "one operator behind both handles: self-escrow"

GLASS_JUSTIFICATION = (
    "The partner bank's fraud desk calls at 17:00 about the mule account. "
    "The liaison note naming it is TLP:GREEN and I hold CLEAR; reading that "
    "one note before the call.")

HOLD_REASON = (
    "Preservation notice from Latticework Holdings' counsel, ref "
    "DEMO/2026/LH-01 (fiction): keep the message and everything derived "
    "from it until the civil claim is resolved.")

#: How far back the two earlier analytics runs look, in months. Earliest
#: first, so each run's start time rises with its as-of and the trend reads
#: left to right the way the network grew. Neither is a month demo-network
#: dates a tie at, so a day either way cannot move a tie across the line.
#: At 17 months mer_florin has no tie yet (betweenness 0); at 9.5 it is the
#: one path from the rest to oriel (9); now oriel reaches the bitwright crew
#: through it too (45). A trend that rises, which is the promotion docs/03
#: says a series exists to show.
TREND_MONTHS = (17, 9.5)

def ago(months: float) -> datetime:
    """World time, months back, the way demo-network dates its ties."""
    return datetime.now(timezone.utc) - timedelta(days=int(months * 30.44))


def _when(when) -> datetime | None:
    """A date as the tables give it: months back, an exact moment, or none."""
    if when is None or isinstance(when, datetime):
        return when
    return ago(when)


class Tally:
    """What each item made and what it found already there, for the
    summary and for the second run to say it doubled nothing."""

    def __init__(self) -> None:
        self.made: dict[str, int] = {}
        self.kept: dict[str, int] = {}

    def add(self, item: str, n: int = 1) -> None:
        self.made[item] = self.made.get(item, 0) + n

    def keep(self, item: str, n: int = 1) -> None:
        self.kept[item] = self.kept.get(item, 0) + n

    def word(self, item: str) -> str:
        made, kept = self.made.get(item, 0), self.kept.get(item, 0)
        if made and kept:
            return f"+{made}, {kept} already there"
        if made:
            return f"+{made}"
        return f"{kept} already there" if kept else "nothing"


# ----------------------------------------------------------------- accounts

def ensure_account(conn, *, email: str, name: str, clearance: str,
                   roles: list[str], tally: Tally):
    """An account made the way `bootstrap.py create-user` makes one: the
    user, its clearance, its global roles, an enrolled TOTP secret and a
    USER_CREATED audit row, in one transaction. The password is random and
    is never printed or stored anywhere but its Argon2 hash; the officer is
    reached with `bootstrap.py session` when a shot needs it."""
    import secrets as _secrets

    from psycopg.types.json import Json

    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore

    row = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (email,)).fetchone()
    if row is not None:
        tally.keep("accounts")
        return row[0]
    if not os.environ.get("NOCTORNAL_TOTP_KEK"):
        raise SystemExit(
            "NOCTORNAL_TOTP_KEK is not set. It seals the new accounts' TOTP "
            "secrets and lives in .env.local; generating one here would seal "
            "them under a key the API does not hold (scripts/_env.py R9).")
    store = PgUserStore(conn)
    with conn.transaction():
        user_id = store.create_user(email, name, _secrets.token_urlsafe(24))
        conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                     (clearance, user_id))
        for role in roles:
            conn.execute(
                """INSERT INTO iam.user_role (user_id, role_key)
                   VALUES (%s, %s) ON CONFLICT DO NOTHING""", (user_id, role))
        store.enroll_totp(user_id, totp.generate_secret())
        conn.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id, detail)
               VALUES (NULL, 'SYSTEM', 'USER_CREATED', 'app_user', %s, %s)""",
            (user_id, Json({"email": email, "roles": roles,
                            "tlp_clearance": clearance,
                            "via": "scripts/seed_readme_showcase.py"})))
    tally.add("accounts")
    return user_id


# -------------------------------------------------------------------- graph

def _node(conn, case_id, label: str, node_type: str | None = None):
    row = conn.execute(
        """SELECT id FROM core.node
            WHERE case_id = %s AND label = %s AND deleted_at IS NULL
              AND merged_into_id IS NULL
              AND (%s::text IS NULL OR node_type = %s)
            ORDER BY created_at LIMIT 1""",
        (case_id, label, node_type, node_type)).fetchone()
    return row[0] if row else None


def _edge(conn, case_id, src, etype: str, dst, *, inferred: bool | None = None):
    row = conn.execute(
        """SELECT id FROM core.edge
            WHERE case_id = %s AND src_node_id = %s AND edge_type = %s
              AND dst_node_id = %s AND deleted_at IS NULL
              AND (%s::boolean IS NULL OR is_inferred = %s)
            ORDER BY created_at LIMIT 1""",
        (case_id, src, etype, dst, inferred, inferred)).fetchone()
    return row[0] if row else None


def seed_entities(conn, case_id, owner, tally: Tally) -> dict:
    """The GROUP, WALLET and INFRA entities and their structural ties."""
    from noctornal_api.graph import AssertionInput, GraphWriteService

    graph = GraphWriteService(conn)
    ids: dict = {}
    for node_type, label, attrs, when, grade in ENTITIES:
        found = _node(conn, case_id, label, node_type)
        if found is not None:
            ids[label] = found
            tally.keep("entities")
            continue
        valid_from = _when(when)
        ids[label] = graph.create_node(
            case_id=case_id, node_type=node_type, label=label,
            created_by=owner, attrs=attrs, classification="CLEAR",
            valid_from=valid_from,
            assertion=AssertionInput(created_by=owner, observed_at=valid_from,
                                     **grade))
        tally.add("entities")
    for etype, src, dst, when, grade in STRUCTURAL:
        s = ids.get(src) or _node(conn, case_id, src)
        d = ids.get(dst) or _node(conn, case_id, dst)
        if _edge(conn, case_id, s, etype, d) is not None:
            tally.keep("structural")
            continue
        valid_from = _when(when)
        graph.create_edge(
            case_id=case_id, edge_type=etype, src_node_id=s, dst_node_id=d,
            created_by=owner, classification="CLEAR", valid_from=valid_from,
            assertion=AssertionInput(created_by=owner, observed_at=valid_from,
                                     **grade))
        tally.add("structural")
    return ids


# ----------------------------------------------------------------- evidence

def seed_exhibits(conn, case_id, owner, storage, tally: Tally) -> dict:
    """The exhibits, and their links to what they support.

    The object lock and the retention date are the service's default, as
    they are for every other seeder's exhibits: a shorter lock of this
    seeder's own made these four read "retain until" a month out beside the
    .eml's year in the same register (README screenshot review, 2026-09-23,
    verifier round). tests/conftest.py still cuts the default to a day
    through EVIDENCE_RETENTION_DAYS."""
    from noctornal_api.evidence import EvidenceService

    svc = EvidenceService(conn, storage)
    now = datetime.now(timezone.utc)
    out: dict = {}
    for (title, mtype, data, method, tlp, days, url, description, labels,
         ties, why) in EXHIBITS:
        row = conn.execute(
            "SELECT id FROM core.evidence WHERE case_id = %s AND title = %s",
            (case_id, title)).fetchone()
        if row is not None:
            # Not ingested again: a re-ingest of identical bytes is a real
            # re-acquisition and writes its own custody row, which would be
            # a second run doubling the log.
            out[title] = row[0]
            tally.keep("exhibits")
        else:
            out[title] = svc.ingest(
                case_id=case_id, title=title, media_type=mtype, data=data,
                acquired_by=owner, acquisition_method=method,
                acquired_at=now - timedelta(days=days), classification=tlp,
                source_url=url, description=description).evidence_id
            tally.add("exhibits")
        for label in labels:
            node_id = _node(conn, case_id, label)
            if _linked(conn, out[title], node_id=node_id):
                tally.keep("links")
                continue
            svc.link_to_node(evidence_id=out[title], node_id=node_id,
                             created_by=owner, relevance=why)
            tally.add("links")
        for src, etype, dst, quote in ties:
            edge_id = _edge(conn, case_id, _node(conn, case_id, src), etype,
                            _node(conn, case_id, dst), inferred=False)
            if _linked(conn, out[title], edge_id=edge_id):
                tally.keep("links")
                continue
            svc.link_to_edge(evidence_id=out[title], edge_id=edge_id,
                             created_by=owner, relevance=f'"{quote}"',
                             page_ref=quote_line(data, quote))
            tally.add("links")
    return out


def quote_line(data: bytes, quote: str) -> str | None:
    """'line N' for a quote in a text exhibit, so the inspector's evidence
    list can say where it is; None when the quote is not in the bytes (the
    image's quotes are from its description)."""
    for n, line in enumerate(data.decode("latin-1").splitlines(), start=1):
        if quote in line:
            return f"line {n}"
    return None


def _linked(conn, evidence_id, *, node_id=None, edge_id=None) -> bool:
    if node_id is None and edge_id is None:
        raise SystemExit("an exhibit link names something this case does not "
                         "hold: was demo-network run on this case?")
    return conn.execute(
        """SELECT 1 FROM core.evidence_link
            WHERE evidence_id = %s
              AND node_id IS NOT DISTINCT FROM %s
              AND edge_id IS NOT DISTINCT FROM %s""",
        (evidence_id, node_id, edge_id)).fetchone() is not None


#: How long the database's clock must read past a stamp, without a break,
#: before this seeder writes the next row the server stamps. Measured on
#: this dev stack on 2026-09-23: the database runs in WSL, whose clock
#: steps between the host's time and about 12.6 seconds behind it, and has
#: held the host's time for at most about a second at a stretch (1,705
#: readings over 20 seconds). Rows stamped by the server's clock (a custody
#: row's `occurred_at`, a run's `started_at`) then land out of causal
#: order, and the console sorts by them: in one test run the .eml's log
#: read VIEWED, HASH_VERIFIED, ACQUIRED (README screenshot review,
#: 2026-09-23, verifier round).
CLOCK_WINDOW = 1.5


def after_clock(conn, stamp) -> None:
    """Return once the database's clock has read past `stamp` for
    CLOCK_WINDOW seconds without a break, so the SLOWER of its two clocks
    has passed it and the next stamped row sorts after it whichever clock
    stamps it. On a stack whose clock does not step, that is the window
    and nothing more."""
    if stamp is None:
        return
    import time

    give_up = time.monotonic() + 40
    since = None
    while True:
        past = conn.execute("SELECT clock_timestamp() > %s",
                            (stamp,)).fetchone()[0]
        now = time.monotonic()
        if past:
            since = now if since is None else since
            if now - since >= CLOCK_WINDOW:
                return
        else:
            since = None
            if now > give_up:
                raise SystemExit(
                    f"the database's clock has not passed {stamp.isoformat()} "
                    "in 40 seconds; the rows it stamps next would sort before "
                    "the rows they follow, so the seed stopped")
        time.sleep(0.05)


def _last_touch(conn, evidence_id):
    return conn.execute(
        "SELECT max(occurred_at) FROM core.evidence_custody WHERE evidence_id = %s",
        (evidence_id,)).fetchone()[0]


def seed_custody(conn, case_id, owner, storage, anchor, tally: Tally) -> None:
    """One read, then one integrity check, by the analyst, through the same
    two calls the console's Open and Verify make. In that order, so the log
    reads ACQUIRED, VIEWED, HASH_VERIFIED; once, so it does not grow with
    every rebuild or every shoot."""
    from noctornal_api.evidence import EvidenceService

    svc = EvidenceService(conn, storage)
    done = {r[0] for r in conn.execute(
        """SELECT action FROM core.evidence_custody
            WHERE evidence_id = %s AND actor_id = %s""", (anchor, owner))}
    if "VIEWED" in done:
        tally.keep("custody")
    else:
        after_clock(conn, _last_touch(conn, anchor))
        svc.view(anchor, owner)
        tally.add("custody")
    if "HASH_VERIFIED" in done:
        tally.keep("custody")
    else:
        after_clock(conn, _last_touch(conn, anchor))
        if not svc.verify_integrity(anchor, owner):
            raise SystemExit("the anchor exhibit failed its integrity check; "
                             "an alarm was raised and the seed stopped")
        tally.add("custody")


def seed_hold(conn, anchor, owner, tally: Tally) -> None:
    from noctornal_api.retention import RetentionService

    held = conn.execute("SELECT legal_hold FROM core.evidence WHERE id = %s",
                        (anchor,)).fetchone()[0]
    if held:
        tally.keep("hold")
        return
    RetentionService(conn).set_legal_hold(anchor, actor_id=owner, on=True,
                                          reason=HOLD_REASON)
    tally.add("hold")


# ---------------------------------------------------------------- selectors

def seed_selectors(conn, case_id, tally: Tally) -> None:
    from noctornal_api.selectors import SelectorStore

    store = SelectorStore(conn)
    for sel_type, raw, owner_label, months in SELECTORS:
        # `record` upserts and COUNTS a repeat observation, so a second run
        # calling it would bump observation_cnt: look first.
        if store.find(case_id=case_id, selector_type=sel_type,
                      raw_value=raw) is not None:
            tally.keep("selectors")
            continue
        store.record(case_id=case_id, selector_type=sel_type, raw_value=raw,
                     node_id=_node(conn, case_id, owner_label),
                     observed_at=_when(months))
        tally.add("selectors")


# -------------------------------------------------------------------- comms

def seed_comms(conn, case_id, owner, colleague, tally: Tally) -> None:
    """Two bindings on durable identifiers, the conversation the inferred tie
    rests on, a case stoplist entry for the forum escrow, and the advert's
    contact block, all at CLEAR."""
    from noctornal_api.comms import (
        CLAIMED,
        PLATFORM_DISCLOSURE,
        CommsService,
        normalise,
    )
    from noctornal_api.contact_blocks import ContactBlockService

    comms = CommsService(conn)
    kite = _node(conn, case_id, "mer_kite")
    oriel = _node(conn, case_id, "oriel")
    for platform, observed, identity, ref in (
            ("TOX", TOX_ROTATED, kite, "http://nightmarket.example/t/7702"),
            ("TELEGRAM", TELEGRAM_ID, oriel, None)):
        durable = normalise(platform, observed).durable
        if conn.execute(
                """SELECT 1 FROM comms.channel_binding
                    WHERE case_id = %s AND platform_key = %s
                      AND durable_value = %s AND identity_node_id = %s""",
                (case_id, platform, durable, identity)).fetchone():
            tally.keep("bindings")
            continue
        comms.bind(case_id=case_id, platform_key=platform, observed=observed,
                   created_by=owner, identity_node_id=identity,
                   verification=CLAIMED, co_declaration_ref=ref,
                   classification="CLEAR")
        tally.add("bindings")

    # Metadata only: who wrote to whom and when, disclosed by the server's
    # operator. It is what the inferred tie's rationale points at, so the
    # suggestion is traceable to something the case holds.
    conversation = comms.open_conversation(
        case_id=case_id, platform_key="XMPP",
        provenance_class=PLATFORM_DISCLOSURE,
        external_ref="xmpp.bitwright.example/dm/forge-lathe",
        legal_authority="Production order DEMO/2026/0002-P1 to the server "
                        "operator (fiction): connection and message metadata "
                        "only, no content",
        classification="CLEAR")
    new_messages = 0
    for handle, days in (("bit_forge@xmpp.bitwright.example", 40),
                         ("bit_lathe@xmpp.bitwright.example", 39),
                         ("bit_forge@xmpp.bitwright.example", 25)):
        sent = datetime(2026, 9, 1, 20, 0, tzinfo=timezone.utc) - timedelta(days=days)
        if comms.add_message(conversation, sender_handle=handle, body=None,
                             sent_at=sent) is not None:
            new_messages += 1
    if new_messages:
        tally.add("conversation")
    else:
        tally.keep("conversation")

    blocks = ContactBlockService(conn)
    try:
        # Before the parse, so the escrow line carries its stoplist warning
        # rather than only the parser's label heuristic.
        blocks.add_stoplist_entry(
            durable_or_observed="nm_escrow@jabber.example", role="ESCROW",
            added_by=owner, platform_key="XMPP",
            service_name="nightmarket forum escrow",
            note="The forum's escrow agent, quoted in vendors' blocks.",
            case_id=case_id)
        tally.add("stoplist")
    except Exception as exc:  # noqa: BLE001 - only "already there" is expected
        if "already on the stoplist" not in str(exc):
            raise
        tally.keep("stoplist")
    parsed = blocks.parse_and_store(
        case_id=case_id, raw_text=CONTACT_BLOCK, source_ref=CONTACT_SOURCE,
        created_by=colleague, publisher_handle="mer_kite",
        publisher_identity_node_id=kite, classification="CLEAR",
        visible_case_ids=(case_id,))
    if parsed.get("already_parsed"):
        tally.keep("contact block")
    else:
        tally.add("contact block")


# ------------------------------------------------------- inferred tie, triage

def seed_inferred(conn, case_id, owner, tally: Tally) -> None:
    """One inferred tie INSIDE the bitwright crew, through the only path an
    inferred edge has into the graph: a machine's proposal, accepted by a
    person, who then weighs it at 0 through the console's edge correction
    (`GraphWriteService.update_edge` with its assertion, and the
    EDGE_UPDATED audit row the route writes beside it). Parallel to the
    bit_forge / bit_lathe vouch, and at weight 0, so the analytics graph is
    the one demo-network made: the module docstring has the measurements.

    One transaction, so a run that dies between the acceptance and the
    correction leaves neither; an estate that has the tie at another weight
    (the first version of this seeder left it at 1) gets the correction."""
    from psycopg.types.json import Json

    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.proposals import KIND_EDGE, ProposalReview, ProposalStore

    forge = _node(conn, case_id, "bit_forge")
    lathe = _node(conn, case_id, "bit_lathe")
    edge = _edge(conn, case_id, forge, "COMMUNICATES_WITH", lathe, inferred=True)
    if edge is not None and conn.execute(
            "SELECT weight = 0 FROM core.edge WHERE id = %s", (edge,)).fetchone()[0]:
        tally.keep("inferred")
        return
    with conn.transaction():
        if edge is None:
            payload = {"edge_type": "COMMUNICATES_WITH",
                       "src_node_id": str(forge), "dst_node_id": str(lathe),
                       "classification": "CLEAR"}
            row = conn.execute(
                """SELECT id FROM collect.proposal
                    WHERE case_id = %s AND kind = %s AND origin = %s
                      AND payload @> %s::jsonb AND state = 'PROPOSED'""",
                (case_id, KIND_EDGE, INFERRED_ORIGIN, Json(payload))).fetchone()
            proposal = row[0] if row else ProposalStore(conn).propose(
                case_id=case_id, kind=KIND_EDGE, payload=payload,
                origin=INFERRED_ORIGIN, score=0.6, rationale=INFERRED_RATIONALE)
            ProposalReview(conn).accept(
                proposal, reviewed_by=owner, classification="CLEAR",
                note="Consistent with the room export; kept inferred until "
                     "the content is seen.")
            edge = conn.execute(
                "SELECT applied_edge_id FROM collect.proposal WHERE id = %s",
                (proposal,)).fetchone()[0]
        previous = conn.execute("SELECT weight FROM core.edge WHERE id = %s",
                                (edge,)).fetchone()[0]
        GraphWriteService(conn).update_edge(
            edge, case_id=case_id, weight=0.0,
            assertion=AssertionInput(
                basis="ANALYST_INFERENCE", created_by=owner,
                reliability="F", credibility="6", confidence="LOW",
                rationale=INFERRED_WEIGHT_NOTE,
                claim_path="weight", claim_value={"weight": 0.0}))
        # The route's audit row, carrying the value the correction
        # overwrote: the column no longer holds it (routers/graph.py
        # `_audit_change`), and weights go in as text, never as a float.
        conn.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', 'EDGE_UPDATED', 'edge', %s, %s, %s)""",
            (owner, edge, case_id,
             Json({"fields": ["weight"], "previous": {"weight": str(previous)}})))
    tally.add("inferred")


def seed_triage(conn, case_id, owner, colleague, tally: Tally) -> None:
    """The colleague pastes the advert thread; extraction raises proposals
    and the case owner is told, as the capture route does, and has read
    that notice, so the inbox shows both states. The owner parks the forum
    escrow as DISPUTED.

    The capture, its audit row, the notice and its reading are one
    transaction. Apart, a run that died after the capture left proposals
    with no audit row and no notice, and the next run found the proposals,
    raised nothing, and so never wrote either (README screenshot review,
    2026-09-23, verifier round)."""
    from psycopg.types.json import Json

    from noctornal_api import notify_events
    from noctornal_api.extraction import CaptureService
    from noctornal_api.notifications import NotificationService
    from noctornal_api.proposals import ProposalReview

    with conn.transaction():
        # Through the service and not the HTTP route: the route is rate
        # limited, and this is the call it makes (README screenshot review,
        # 04-triage).
        result = CaptureService(conn).capture(
            case_id=case_id, text=TRIAGE_THREAD, title=TRIAGE_TITLE,
            external_url=TRIAGE_URL, author_handle="mer_kite",
            classification="CLEAR")
        if result.proposal_ids:
            tally.add("proposals", len(result.proposal_ids))
            # The capture route's own audit line, written beside its service
            # call, so the audit trail says who pasted it. Only when this
            # run raised something: a second run pastes nothing new.
            conn.execute(
                """INSERT INTO audit.event
                       (actor_id, actor_kind, action, object_type, object_id,
                        case_id, detail)
                   VALUES (%s, 'USER', 'DOCUMENT_CAPTURED', 'document',
                           %s, %s, %s)""",
                (colleague, result.document_id, case_id,
                 Json(result.summary())))
            if notify_events.proposals_queued(
                    conn, case_id=case_id, count=len(result.proposal_ids),
                    actor_id=colleague):
                queued = conn.execute(
                    """SELECT id FROM notify.notification
                        WHERE recipient_id = %s AND kind = 'PROPOSAL_QUEUED'
                          AND case_id = %s
                        ORDER BY created_at DESC LIMIT 1""",
                    (owner, case_id)).fetchone()[0]
                NotificationService(conn).mark_read(queued, owner)
        else:
            tally.keep("proposals", result.skipped_existing)

    row = conn.execute(
        """SELECT id, state FROM collect.proposal
            WHERE case_id = %s AND kind = 'NODE'
              AND payload->>'label' = %s""",
        (case_id, DISPUTED_VALUE)).fetchone()
    if row is not None and row[1] == "PROPOSED":
        ProposalReview(conn).defer(row[0], reviewed_by=owner, note=DISPUTED_NOTE)
        tally.add("disputed")
    elif row is not None:
        tally.keep("disputed")


# ----------------------------------------------------- notifications, glass

def seed_approval(conn, case_id, colleague, tally: Tally) -> None:
    """A real four-eyes request from the colleague. `ApprovalService.request`
    notifies everyone on the case who could approve it, which is the owner:
    an unread NORMAL notice with its Open approvals button. It expires with
    its eight hour TTL like any other; rebuild the estate before a shoot."""
    from noctornal_api.approvals import ApprovalService

    if conn.execute(
            """SELECT 1 FROM core.approval_request
                WHERE case_id = %s AND operation = 'node.merge'
                  AND requested_by = %s""", (case_id, colleague)).fetchone():
        tally.keep("approval")
        return
    # The shape `routers/merges.merge_payload` builds, so the approval could
    # be consumed by the merge it names if anyone ever signed it.
    payload = {"source_node_id": str(_node(conn, case_id, "mer_ash")),
               "target_node_id": str(_node(conn, case_id, "mer_kite")),
               "reason": APPROVAL_REASON, "basis_selector_id": None}
    # With its notice, or not at all. The service logs a failed notice and
    # returns the request anyway (right for a person at the console, who
    # can see it), and the check above would then skip it on every later
    # run, so an inbox the README promises would stay one notice short.
    with conn.transaction():
        made = ApprovalService(conn).request(
            operation="node.merge", case_id=case_id, payload=payload,
            justification=APPROVAL_JUSTIFICATION, requested_by=colleague)
        if not made.approvers_notified:
            raise SystemExit("the approval request reached nobody, so it was "
                             "not kept; run the seeder again")
    tally.add("approval")


def seed_break_glass(conn, case_id, owner, colleague, storage, green_id,
                     tally: Tally) -> None:
    """The colleague, cleared for CLEAR, breaks glass to GREEN to read the
    one GREEN note, reads it, and ends the grant. The owner gets the URGENT
    notice and the officer the case-free alert, both from the service's own
    `_alert`. Left for the officer to review: see the module docstring.

    One transaction. The check below skips the step once any grant exists,
    so apart, a run that died after the invoke left a live, unused grant
    raising the colleague to GREEN that no later run would end (README
    screenshot review, 2026-09-23, verifier round)."""
    from noctornal_api.break_glass import BreakGlassService
    from noctornal_api.evidence import EvidenceService

    if conn.execute(
            "SELECT 1 FROM iam.break_glass WHERE user_id = %s AND case_id = %s",
            (colleague, case_id)).fetchone():
        tally.keep("break-glass")
        return
    glass = BreakGlassService(conn)
    # The note was ingested moments ago in this run; its read must sort
    # after its acquisition (see CLOCK_WINDOW). Before the transaction,
    # because the custody row takes the transaction's start time.
    after_clock(conn, _last_touch(conn, green_id))
    with conn.transaction():
        grant = glass.invoke(user_id=colleague, case_id=case_id,
                             justification=GLASS_JUSTIFICATION,
                             classification="GREEN",
                             duration=timedelta(hours=1))
        # `invoke` logs a failed alert and keeps the grant, as it must for a
        # person in an emergency. Here that would be an inbox without the
        # urgent notice it is seeded for, and no later run to add it.
        if conn.execute(
                """SELECT 1 FROM notify.notification
                    WHERE recipient_id = %s AND case_id = %s
                      AND kind = 'BREAK_GLASS_INVOKED'""",
                (owner, case_id)).fetchone() is None:
            raise SystemExit("the break-glass notice did not reach the case "
                             "owner, so the grant was not kept; run the "
                             "seeder again")
        # The read the grant was for, counted the way the access gate
        # counts it (`PgAccessResolver.resolve` records the permission it
        # allowed).
        EvidenceService(conn, storage).view(green_id, colleague)
        glass.record_use(grant.id, action="evidence.read", case_id=case_id)
        glass.revoke(grant.id, actor_id=colleague)
    tally.add("break-glass")


# ---------------------------------------------------------------- analytics

def seed_runs(conn, case_id, owner, tally: Tally) -> None:
    """Completed runs at two earlier as-of dates and now, so the Trend draws
    a line. Last, because a run describes the graph it was computed over and
    everything above changes it. A second run is a cache hit on the graph
    hash and stores nothing."""
    from noctornal_api.analytics import AnalyticsParams
    from noctornal_api.analytics_runs import AnalyticsRunService
    from noctornal_api.projections import Projection

    clearance, compartments = conn.execute(
        "SELECT tlp_clearance::text, compartments FROM iam.app_user WHERE id = %s",
        (owner,)).fetchone()
    runs = AnalyticsRunService(conn, clearance=clearance,
                               compartments=frozenset(compartments or []),
                               actor_id=owner)
    # The console's default projection (state.proj in app.js: All ties,
    # inferred in, LOW) and the router's default parameters, so the run
    # stored for "now" is the one the Analysis pane loads.
    params = AnalyticsParams()
    # Anchored to the case, not to this run's clock. as_of is part of the
    # projection's fingerprint, so a date taken from now() is a new
    # projection on every run and a second run stored two more runs (found
    # by running it twice). Midnight of the case's creation day, minus the
    # months, is the same on every run; demo-network dates its ties from
    # that same moment, and TREND_MONTHS avoids the months it uses.
    created = conn.execute('SELECT created_at FROM core."case" WHERE id = %s',
                           (case_id,)).fetchone()[0].astimezone(timezone.utc)
    anchor = created.replace(hour=0, minute=0, second=0, microsecond=0)
    trend = [anchor - timedelta(days=int(m * 30.44)) for m in TREND_MONTHS]
    # The Trend plots runs by `started_at`, which the server stamps, so each
    # run must start after the one before it on the server's slower clock,
    # or the line zigzags (see CLOCK_WINDOW).
    stamp = None
    for as_of in trend + [None]:
        p = Projection(case_id=case_id, preset="all", include_inferred=True,
                       min_confidence="LOW", as_of=as_of)
        after_clock(conn, stamp)
        result = runs.suite(p, params)
        (tally.keep if result.cached else tally.add)("runs")
        stamp = None if result.cached else conn.execute(
            "SELECT started_at FROM analytics.metric_run WHERE id = %s",
            (result.run_id,)).fetchone()[0]
    p = Projection(case_id=case_id, preset="all", include_inferred=True,
                   min_confidence="LOW")
    result = runs.key_player(p, params, n_remove=3)
    (tally.keep if result.cached else tally.add)("runs")


def coverage(conn, case_id, owner) -> dict:
    from noctornal_api.projections import GraphService, Projection

    clearance, compartments = conn.execute(
        "SELECT tlp_clearance::text, compartments FROM iam.app_user WHERE id = %s",
        (owner,)).fetchone()
    graph = GraphService(conn, clearance=clearance,
                         compartments=frozenset(compartments or []))
    return graph.metrics(Projection(case_id=case_id, preset="all",
                                    include_inferred=True))["evidence_coverage"]


# --------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Seed the README showcase case (development only).")
    parser.add_argument("--case", default=DEFAULT_CASE, help="case CODE")
    parser.add_argument("--owner-email", required=True,
                        help="the case owner: the analyst the shots are taken as")
    parser.add_argument("--colleague-email", default=DEFAULT_COLLEAGUE,
                        help="the second account, who acts so the owner is told")
    parser.add_argument("--officer-email", default=DEFAULT_OFFICER,
                        help="the SECURITY_OFFICER who reviews break-glass")
    args = parser.parse_args(argv)

    from noctornal_api.config import ENV_VAR, PRODUCTION

    if os.environ.get(ENV_VAR, "").strip().lower() == PRODUCTION:
        # It creates accounts and a break-glass grant. Development only is a
        # rule here, not a hint in a docstring.
        print(f"refused: {ENV_VAR}={PRODUCTION}. This writes fictional "
              "accounts, a break-glass grant and demo material, and is for "
              "development estates only.", file=sys.stderr)
        return 2

    os.environ.setdefault("NOCTORNAL_PROHIBITED_CONTENT_POLICY",
                          "DEV-POLICY-0 (development seed, not a real policy)")
    os.environ.setdefault("NOCTORNAL_DESIGNATED_PERSON", "dev operator")

    from noctornal_api.db import connect

    conn = connect()
    try:
        return _run(conn, args)
    finally:
        # Also when a step raises: its transaction has already rolled back,
        # and the next run finishes what this one started.
        conn.close()


def _run(conn, args) -> int:
    from noctornal_api.cases import CaseService
    from noctornal_api.evidence import EvidenceStorage

    row = conn.execute(
        'SELECT id, owner_user_id, classification::text FROM core."case" '
        'WHERE code = %s', (args.case,)).fetchone()
    if row is None:
        print(f"no case {args.case!r}; run bootstrap.py demo-network first",
              file=sys.stderr)
        return 1
    case_id, owner, case_tlp = row
    analyst = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                           (args.owner_email,)).fetchone()
    if analyst is None or analyst[0] != owner:
        # Every notice here goes to the case OWNER (that is who the platform
        # tells), so seeding for anyone else would fill the wrong inbox.
        print(f"{args.owner_email} is not the owner of {args.case}",
              file=sys.stderr)
        return 1
    if case_tlp != "CLEAR":
        print(f"{args.case} is {case_tlp}; the showcase material is CLEAR and "
              f"the floor trigger refuses it below the case. Build the case "
              f"with demo-network --classification CLEAR.", file=sys.stderr)
        return 1
    if _node(conn, case_id, "bit_forge", "IDENTITY") is None:
        print(f"{args.case} has no demo-network personas", file=sys.stderr)
        return 1

    tally = Tally()
    storage = EvidenceStorage()

    colleague = ensure_account(conn, email=args.colleague_email,
                               name=COLLEAGUE_NAME, clearance="CLEAR",
                               roles=["CASE_OWNER"], tally=tally)
    ensure_account(conn, email=args.officer_email, name=OFFICER_NAME,
                   clearance="RED", roles=["SECURITY_OFFICER"], tally=tally)
    if conn.execute(
            """SELECT 1 FROM iam.case_assignment
                WHERE case_id = %s AND user_id = %s""",
            (case_id, colleague)).fetchone() is None:
        CaseService(conn).assign_user_checked(case_id, colleague, "ANALYST",
                                              granted_by=owner)

    seed_entities(conn, case_id, owner, tally)
    exhibits = seed_exhibits(conn, case_id, owner, storage, tally)
    eml = conn.execute(
        "SELECT id FROM core.evidence WHERE case_id = %s AND title = %s",
        (case_id, EML_TITLE)).fetchone()
    # The .eml carries the read, the check and the hold when
    # seed_deception_demo has run; otherwise the escrow thread does.
    anchor_title = EML_TITLE if eml else EXHIBITS[0][0]
    anchor = eml[0] if eml else exhibits[EXHIBITS[0][0]]
    if eml and _linked(conn, eml[0], node_id=_node(conn, case_id, PORTAL)):
        tally.keep("links")
    elif eml:
        from noctornal_api.evidence import EvidenceService
        EvidenceService(conn, storage).link_to_node(
            evidence_id=eml[0], node_id=_node(conn, case_id, PORTAL),
            created_by=owner,
            relevance="The portal the message sends its reader to is on "
                      "this domain")
        tally.add("links")
    seed_custody(conn, case_id, owner, storage, anchor, tally)
    seed_hold(conn, anchor, owner, tally)
    seed_selectors(conn, case_id, tally)
    seed_comms(conn, case_id, owner, colleague, tally)
    seed_inferred(conn, case_id, owner, tally)
    seed_triage(conn, case_id, owner, colleague, tally)
    seed_approval(conn, case_id, colleague, tally)
    seed_break_glass(conn, case_id, owner, colleague, storage,
                     exhibits[GREEN_TITLE], tally)
    seed_runs(conn, case_id, owner, tally)

    cov = coverage(conn, case_id, owner)
    counts = conn.execute(
        """SELECT (SELECT count(*) FROM collect.proposal
                    WHERE case_id = %s AND state = 'PROPOSED'),
                  (SELECT count(*) FROM collect.proposal
                    WHERE case_id = %s AND state = 'DISPUTED'),
                  (SELECT count(*) FROM notify.notification
                    WHERE recipient_id = %s AND case_id = %s
                      AND read_at IS NULL)""",
        (case_id, case_id, owner, case_id)).fetchone()

    fresh = bool(tally.made)
    print(f"README showcase extras on {args.case}, TLP:CLEAR unless marked:")
    print(f"  accounts   {tally.word('accounts')}: {args.colleague_email} "
          f"(ANALYST here, CLEAR), {args.officer_email} (SECURITY_OFFICER); "
          f"passwords random, never shown")
    print(f"  entities   {tally.word('entities')} (3 GROUP, WALLET, INFRA); "
          f"structural ties {tally.word('structural')}, none social")
    print(f"  exhibits   {tally.word('exhibits')}; one is GREEN "
          f"({GREEN_TITLE}, unlinked): a CLEAR report withholds it")
    print(f"  evidence   links {tally.word('links')}; {cov['nodes']} entities "
          f"and {cov['edges']} ties of {cov['elements']} elements rest on an "
          f"exhibit ({round(100 * (cov['ratio'] or 0))}%)")
    print(f"  custody    {anchor_title}: read and verified by the analyst "
          f"({tally.word('custody')}); legal hold {tally.word('hold')}")
    print(f"  inferred   bit_forge / bit_lathe COMMUNICATES_WITH, proposed, "
          f"accepted, weighed at 0 ({tally.word('inferred')})")
    print(f"  selectors  {tally.word('selectors')} on 5 personas and the wallet")
    print(f"  comms      bindings {tally.word('bindings')} (Tox mer_kite, "
          f"Telegram oriel); conversation {tally.word('conversation')}; "
          f"contact block {tally.word('contact block')}")
    print(f"  triage     {counts[0]} proposed, {counts[1]} disputed "
          f"(capture {tally.word('proposals')})")
    print(f"  inbox      {counts[2]} unread for the owner (urgent break-glass, "
          f"approval request); proposals notice read")
    print(f"  lifecycle  break-glass {tally.word('break-glass')}: ended, "
          f"awaiting officer review; nothing past retention (see docstring)")
    print(f"  analytics  runs {tally.word('runs')}: as of "
          f"{', '.join(f'-{m}mo' for m in TREND_MONTHS)} and now, key player n=3")
    if not fresh:
        print("  second run: every item was already there, nothing was added")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
