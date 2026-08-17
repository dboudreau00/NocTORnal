# 19 — Social-engineering evidence: phishing, vishing, BEC

Status: **decided**, implemented in migrations 0046–0050.
Supersedes nothing. Extends docs/01 (domain model), docs/11 (malware
handling) and docs/16 (legal) into the social-engineering domain.

---

## 0) The question this answers

> Can we add phishing / vishing evidence? Screenshots of phishing pages
> and URLs, records of phone calls or SIP trunks, BEC emails?

Yes. Most of the graph model already fits — `EMAIL`, `PHONE`, `DOMAIN`,
`URL` selectors, `VICTIM` / `ORGANISATION` / `INFRA` / `CAMPAIGN` nodes,
WORM evidence with custody. What is missing is not node types. It is
**provenance structure**: the three things an analyst needs to prove are
each a *tuple*, and this system had nowhere to put the tuple.

| Claim | The evidence is actually… |
|---|---|
| "This page phished our staff" | requested URL → redirect chain → final URL → TLS cert → screenshot → DOM, **all at one timestamp, from one fetch** |
| "This mail is BEC" | the `Received` chain + `From`/`Reply-To` divergence + what SPF/DKIM/DMARC *decided* |
| "This call was the vishing call" | trunk / P-Asserted-Identity / STIR-SHAKEN attestation, **not** the number the victim saw |

A screenshot with no redirect chain proves someone had a screenshot. A
`From:` header with no `Received` chain proves nothing at all.

---

## 1) Two invariants generalise into this domain

These are not new rules. They are existing rules arriving somewhere new,
and both are load-bearing enough to restate.

### 1.1 Invariant 10 — a captured phishing page is attacker-authored code

Invariant 10 ("samples never render, never execute") was written about
malware. A saved phishing DOM is the same hazard with a different
extension: attacker-authored HTML and JavaScript, sitting in a database,
one careless `innerHTML` away from executing **inside the highest-trust
session in the estate** — an authenticated analyst on the case system.

Three consequences, enforced not documented:

1. **DOM, HAR and `.eml` bytes are hostile.** `core.evidence` carries
   `is_hostile_markup`. A hostile row is download-only, and only from the
   separate sample origin — the same gate `lab.sample.download` already
   passes through. The API origin never serves those bytes.
2. **Screenshots are raster-only, and the type is *sniffed*, not
   believed.** `media_type` on `core.evidence` comes from
   `UploadFile.content_type`, which is client-supplied. The inline
   screenshot path re-derives the type from the magic bytes and serves
   what it found, never what it was told. SVG is code and is refused.
3. **The UI renders capture metadata freely and capture bytes never** —
   the same split the lab pane already draws.

### 1.2 Invariant 9 — the displayed identifier is the spoofed one

Invariant 9 ("durable identifiers, not displayed ones") was written about
Tox nospam and recycled Telegram usernames. Its social-engineering form is
sharper, because in this domain the displayed identifier is *chosen by the
attacker as the attack*:

| Domain | What the victim saw (weak) | What is durable |
|---|---|---|
| Voice | presented CLI, CNAM name | originating trunk, P-Asserted-Identity, STIR/SHAKEN attestation |
| Email | `From:`, display name | envelope `MAIL FROM`, a **passing** DKIM `d=`, the first trusted `Received` hop |
| Web | the domain in the address bar | TLS SPKI hash, hosting ASN |

So `deception.call_record` has `presented_number` **and**
`p_asserted_identity` as separate columns, and never one column called
"caller". Collapsing them is how a spoofed number ends up as a strong
`PHONE` selector on a real person's `PERSON` node — attributing a crime to
whoever's number the attacker picked out of the air. That is the
fund-losing bug of this subsystem.

**No selector is minted from a presented value.** The presented CLI is a
column on the record, not a graph selector, until something corroborates
it.

---

## 2) The `Received` chain is only trustworthy inwards

The single most misread artefact in email forensics, and the reason
`deception.email_hop` numbers its rows the way it does.

An SMTP `Received` header is *prepended* by each MTA. So the chain reads
bottom-up in time — but more importantly, **every hop above the first one
your own infrastructure added is attacker-writable**. A BEC sender can
forge as many plausible upstream `Received` lines as they like.

Therefore:

- `seq = 0` is the hop closest to the recipient — the receiving
  organisation's own MTA. Most trustworthy.
- Trust decays monotonically as `seq` rises.
- `is_trusted_boundary` marks the last hop under the recipient's control.
  **Above it, nothing is evidence of anything.**

An analyst who reads the chain top-down attributes the mail to whatever
originating IP the attacker typed. The UI therefore renders the chain
recipient-first with an explicit "trust ends here" rule, and the extractor
refuses to propose an `INFRA` node from a hop above the boundary.

---

## 3) Model

New schema `deception`. Three subsystems, one shape: **a provenance row
that points at WORM exhibits**, never bytes in a column.

### 3.1 Web capture — `deception.capture`, `deception.capture_hop`

The capture row is the tuple. Screenshot, DOM and HAR are three
`core.evidence` FKs on **one** row, so a screenshot cannot be re-paired
with a different page's DOM. That pairing *is* the evidential value.

Carries: requested URL, final URL, method (`MANUAL_BROWSER` /
`HEADLESS` / `VENDOR_API` / `ANALYST_UPLOAD` / `VICTIM_SUPPLIED`), tool,
egress profile, user agent, viewport, HTTP status, liveness, and the TLS
identity — subject, issuer, validity window and **`tls_spki_sha256`**, the
public-key hash that survives domain rotation.

`capture_hop` is the redirect chain: `seq`, URL, status, resolved IP, ASN,
and `hop_kind` (`HTTP_30X` / `META_REFRESH` / `JS` / `FRAME` /
`DNS_CNAME`). Kits chain shortener → compromised host → kit; each hop is a
candidate `INFRA` node and each is separately attributable.

### 3.2 Email — `deception.email_message`, `email_hop`, `email_attachment`

`email_message` stores parsed headers as **separate columns that are
allowed to disagree** — `header_from`, `header_from_display`,
`header_reply_to`, `header_return_path`, `envelope_from` — plus what the
receiving MTA *decided*: `spf_result`, `dkim_result`, `dkim_domain`,
`dmarc_result`, and the raw `Authentication-Results`.

`from_replyto_divergent` is stored, not computed on read, because it is
the finding and a report must be able to cite it.

Attachments carry an optional `sample_id` — a BEC attachment is malware
and belongs in `lab.sample`, under the policy gate that already exists. It
does not get a second, weaker home here.

### 3.3 Telephony — `deception.call_record`

CDR / SIP provenance, with the presented-vs-durable split from §1.2, plus
`record_source` (`CARRIER_CDR` / `PBX_LOG` / `SIP_CAPTURE` /
`VICTIM_STATEMENT`) — a victim's recollection and a carrier CDR are both
admissible and are not the same grade of evidence.

`stir_shaken_attestation` (A/B/C) is the telephony DKIM: attestation A is
the carrier vouching the caller is entitled to that number. It is the only
field on the record that authenticates anything.

**Recordings are interception.** `recording_evidence_id` is `NULL` unless
`recording_lawful_basis` is populated — a DB `CHECK`, the same shape as
the vendor-detonation constraint in `lab`. Metadata is not content; the
constraint sits only on the content.

### 3.4 Ontology — deliberately two additions, not twelve

`CONVENTIONS.md` says ask before adding a node or edge type that duplicates an
existing one. Most of this domain already has a home: a phishing host is
`INFRA`, a kit is `TOOL`, a victim is `VICTIM`, a call is an `EVENT`, a
campaign is a `CAMPAIGN`. Two things had none.

**`LURE`** (node) — the pretext itself: the fake O365 login, the
invoice-redirect story, the "IT support" script. Distinct from `TOOL` (the
kit that *generates* it) and from `CAMPAIGN` (time-bounded and
actor-scoped). Lures recur across campaigns and across actors, and
"the same pretext hit six victims via three senders" is precisely the
question this platform exists to answer.

**`IMPERSONATES`** (edge) — `(IDENTITY, LURE) → (ORGANISATION, PERSON)`.
Nothing existing carries a *false* identity claim: `ALIAS_OF` means the
same actor, `SAME_AS` means the same entity. Impersonation is the opposite
— an assertion that the claim is untrue.

> **Valence 0, and excluded from social projections.** If impersonation
> counted as affiliation, Microsoft would be the most central node in
> every phishing case in the system, and every centrality ranking would be
> garbage. This is invariant 4's concern (structure must not silently
> absorb a different kind of tie) arriving via a new edge.

`TARGETED` is widened to accept `LURE` and `INFRA` as sources rather than
minting a near-duplicate `DELIVERED_TO`.

Four selectors: `TLS_SPKI` (strong — survives domain rotation),
`SIP_URI` (strong), `EMAIL_MSGID` (weak — kits reuse Message-ID formats,
so it is a pivot, not an identity) and `FAVICON_MMH3` (weak — the standard
phishing-infra clustering pivot; a hash collision on a stock favicon would
merge half the internet, so clustering only, never auto-merge).

---

## 4) Where the existing rules bite

| Invariant | How it lands here |
|---|---|
| 1 — nothing is a fact | A capture/message/call row is **evidence**, not graph. Nodes and edges come from it only via `core.assertion`, like everything else. |
| 3 — machines propose | The header parser and the capture parser write `proposal` rows. Neither has a code path to `node` or `edge`. |
| 5 — superseded, never overwritten | A re-capture of the same URL is a **new** capture row. Phishing pages change hourly; overwriting destroys the timeline that proves it. |
| 8 — TLP gates egress | BEC bodies are victim PII by construction. Nothing new: `check_egress` already covers exhibits and reports. |
| 12 — nothing silently dropped | An unparseable `.eml` or CDR row goes to `ingest.dead_letter` with the raw fragment. |

---

## 5) Tradecraft: rendering a BEC email attacks the investigator

Separate from XSS, and less obvious. An HTML email body loads remote
images. Rendering one in the analyst's browser fires the attacker's
tracking pixel — from the investigating organisation's IP, at a timestamp
that tells the actor when the investigation reached them.

So the body is **never** rendered. The UI shows extracted plain text with
URLs defanged (`hxxps://evil[.]com`, non-clickable). Defanging is not
decoration: a mis-click from an analyst workstation is both a tradecraft
disclosure and a drive-by risk, and it happens.

The same reasoning is why `deception.capture.egress_profile_id` exists.
Fetching attacker infrastructure from the office egress IP tells the actor
they are being watched.

---

## 6) Legal — one new blocking item

docs/16 already carries L1 (prohibited content), L2 (stealer-log lawful
basis and retention), L3 (persona operation authority) and L4
(interception). Two of them extend into this domain without amendment:

- **L2** covers victim mailbox content at scale. BEC ingest is squarely
  inside it.
- **L4** covers call *recordings* and live SIP content capture. CDR
  metadata is generally not interception; content is. The `CHECK`
  constraint in §3.3 is the software half; the authority is the other
  half and the software cannot supply it.

**L5 is new — active web capture authority.**

Fetching a phishing page is an *outbound interaction with attacker
infrastructure*. Two distinct exposures:

1. **Attribution.** An attributable fetch discloses the investigation.
   Mitigated in software by requiring an egress profile for any
   non-passive capture method.
2. **Submitting anything to the page is a different act entirely.**
   Entering credentials — including canary or fabricated ones — to see
   what the kit does may constitute unauthorised access, may constitute
   an offence under computer-misuse statutes in several jurisdictions,
   and is not a decision software can make. `deception.capture` therefore
   has `submitted_input boolean` and a `CHECK` that refuses the row unless
   `submission_authority_ref` is present.

As with L1 in Phase 8: the software is built, and refuses to operate the
gated part until a human records the authority. That refusal is the
feature, not an unfinished edge.

---

## 7) What is deliberately not built

- **No live SIP interception.** No packet capture, no RTP, no
  transcription. The model can *hold* a recording someone else lawfully
  obtained; it will not obtain one. That is L4 and it is not ours to
  decide.
- **No credential submission automation.** See L5. There is a column to
  record that a human did it under authority, and no code that does it.
- **No mailbox connector.** Reading a victim's mailbox is L2 plus a
  Phase 4 collection-account problem. `.eml` arrives as an upload or over
  the ingest API; the platform does not hold mailbox credentials.
- **No URL detonation from the UI.** Visiting a phishing URL on demand
  from an analyst's session is the tradecraft leak in §5 with a button on
  it. Captures are recorded, not triggered.
- **No "is this phishing?" classifier.** Machines propose; a verdict
  presented as a fact is invariant 1 with a model attached.
