# 16 — Legal and external dependency register

**Every place where this build has done as much as software can do, and the
rest is a decision somebody has to make outside it.**

Written because the alternative is worse: a system whose legal assumptions
live only in the heads of the people who wrote it ships, changes hands, and
then someone discovers the assumption by breaking it.

Three kinds of entry:

- 🔴 **BLOCKING** — do not operate this in production until it is settled.
  The code may run; running it may not be lawful.
- 🟠 **DETERMINATION** — a policy choice the operator must make and write
  down. The software has picked a defensible default and will do whatever
  it is told instead.
- 🔵 **CONFIRM EXTERNALLY** — a factual claim this build relies on that
  came from documentation, convention or reasoning rather than from an
  authoritative source. Verify before depending on it.

Each entry says **what is built**, **what it assumes**, and **what must be
settled**. Nothing here is legal advice; it is an inventory of the places
where legal advice is required.

---

## 🔴 BLOCKING

### L1 — Prohibited content in the sample store

**Built:** Phase 8 (`samples.py`, Alembic 0031). Ingest is refused until
`NOCTORNAL_PROHIBITED_CONTENT_POLICY` and `NOCTORNAL_DESIGNATED_PERSON` are
set. `REJECTED` destroys the bytes and the data key and keeps the row.

**Assumes:** that somebody has written the policy the environment variable
references. **The software records a declaration; it cannot verify one.** A
false declaration produces a working system and an unlawful deployment.

**Must be settled, with counsel, before the first ingest:**

1. Who is notified, how fast, through what channel, when screening trips.
2. What the `REJECTED` path does with the bytes — quarantine, secure
   destruction, or **preservation under legal instruction**. These
   conflict. The build currently destroys, which is the wrong answer in a
   jurisdiction that requires preservation. `reject(purge_bytes=False)`
   exists for that case and nothing selects it automatically.
3. Reporting obligations in **both** operating jurisdictions (decision 13:
   US and Canada). They differ.
4. Who may see a quarantined item and under what authority.
5. Whether you are authorised to **hold** known-material hash sets at all.
   In most jurisdictions this requires specific authorisation, which is why
   no automated screening is built — see C3.
6. How an analyst's exposure is limited, logged and supported.

### L2 — Stealer logs and third-party personal data at scale

**Built:** Phase 9 (`ingest.py`, Alembic 0033). Operator confirmed
2026-07-25 that stealer logs are in scope. Compartment enforced, victims as
`VICTIM` nodes flagged `is_incidental`, credential values masked by default
with a step-up reveal, per-category retention shorter than the case
default, free-text search across victim PII refused without a logged
authorisation.

**Assumes:** that holding this material has a lawful basis, and that the
basis extends to every victim in the archive — who are, by definition, not
the subjects of the investigation.

**Must be settled, with counsel:**

1. **The lawful basis for holding data about thousands of uninvolved
   people.** This is the single largest data-protection exposure in the
   platform, and docs/12 says so explicitly.
2. Whether victim **notification** obligations attach, and to whom.
3. The retention period. The build defaults `STEALER_LOG` to 90 days,
   enforced independently of the case, which is a guess and is meant to be
   replaced.
4. Whether **session tokens and live credentials** may be held at all, as
   opposed to their metadata. The build can store either; it masks by
   default and the reveal is step-up audited.
5. Cross-border transfer, if any partner or analyst is in a third country.
6. What "minimisation review at closure" must actually produce.

### L3 — Persona operation and computer-misuse exposure

**Built:** Phase 4 (`collection.py`, persona vault). Credentials are
envelope-encrypted and decrypted only in the collector (invariant 7).

**Assumes nothing about authority.** The software will happily drive an
account into a forum. Whether *you* may is not a software question.

**Must be settled, with counsel:**

1. Authority to operate a covert persona against each target, per
   jurisdiction. In several, accessing a system using credentials
   registered under a false identity engages computer-misuse law
   regardless of intent.
2. Whether **passive collection** (reading a public forum) and **active
   collection** (posting, messaging, purchasing) are separately authorised.
   The build distinguishes them (`collection_account.status`, the
   `ACTIVE_ENGAGEMENT` flag) so the authorisation can be modelled, but the
   authorisation itself is external.
3. Entrapment and agent-provocateur exposure for any active engagement.
4. Terms-of-service breach as an independent risk from criminal exposure.

### L4 — Message content capture

**Built:** Phase 7 (`comms.py`, Alembic 0034), message-level capture per
decision 35.

**Must be settled, with counsel:**

1. **Interception law.** Capturing a conversation a persona is *party to*
   is legally distinct from capturing one it is not, and both differ by
   jurisdiction. `conversation.provenance_class` records which, and refuses
   to be null, so the distinction is at least always recorded — but the
   authority is external.
2. One-party vs two-party consent for the recording of communications.
3. Whether captured content of **uninvolved third parties** in a group
   channel is retainable, and for how long.

---

## 🟠 DETERMINATION

### D1 — Dual control on merge defaults to OFF

Decision 44. docs/05 scopes dual control to "the genuinely irreversible",
and a merge here is a reversible ledger. The operator may want it on for
particular cases, or as a standing rule. Per-case switch,
`PUT /cases/{id}/policy`.

### D2 — Withheld-material disclosure defaults to PRESENCE

Decision 49 / migration 0030. An under-cleared analyst is told the picture
is incomplete but not by how much. `NONE` and `COUNT` are available per
case. **The honest limitation is written into the migration:** neither is
leak-proof against differencing, and the compensating control is that
every projection request is audited.

### D3 — Retention periods

Per-case `retention_until` is mandatory and always has been. Phase 6 adds
**per-category** retention that can be shorter and is enforced
independently — `STEALER_LOG` at 90 days is a placeholder. Somebody has to
choose the real numbers, and they are jurisdictional.

### D4 — Purge destroys or preserves

`retention.py` purges on expiry unless `legal_hold` is set. The
**tombstone** survives — what was destroyed, under what authority, by whom.
Whether the default should be destruction at all, versus offline archive,
is an operator decision with a legal input.

### D5 — Detonation exposure

Decision 47. A non-private sandbox submission needs a named authoriser in a
DB constraint. **Which vendors count as "private"** is an operator
determination and depends on contracts this build has not seen. Several
"private" vendor tiers still share hashes with partners.

### D6 — Ingest key holders

docs/12 open question 1. The build assumes keys may be held by external
partners: write-only scope is enforced by a CHECK constraint, IP allowlists
and mandatory expiry exist. If keys are internal-only, the abuse model is
smaller and some of that can relax. If external, a support and revocation
process is needed that the software does not provide.

### D7 — Break-glass reviewer

`break_glass.py` requires a named security officer to review every
invocation. **Who that is** is an operator determination, and the build
will refuse to grant break-glass if no user holds
`SECURITY_OFFICER` — deliberately, because unreviewed emergency access is
just access.

### D8 — Telegram channel and user ids can share one durable value

Added 2026-07-25. **This is a known, unresolved correctness defect that is
reported rather than fixed, and it needs a decision.**

`noctornal_ontology.telegram_id_norm` strips the Bot-API `-100` prefix so
that the two encodings of one supergroup collapse onto each other. Its own
docstring says a chat id and an unrelated user id "must never share a
norm_value" — and stripping the prefix produces exactly that: the channel
`-1001234567890` and the **user** `1234567890` both normalise to
`1234567890`. Correlating on that value reports two unrelated entities as
one actor.

**It was not fixed unilaterally, for two reasons.** Namespacing channels
would re-key every stored `TELEGRAM_ID` selector, which is a data
migration across `core.selector` and `comms.channel_binding`. And it
cannot be done correctly by the normaliser alone: a bare positive number
is a user id in one encoding and a channel id in another, and only the
collector that observed it knows which. Fixing it properly means carrying
the entity type alongside the identifier, which is a model change.

The interim control is that `comms.normalise` now returns a **WARNING on
every `-100…` observation** naming the collision, so an analyst sees it at
the point of use rather than discovering it in a conclusion.

**Determine:** whether to (a) accept the collision with the warning, (b)
namespace channel ids and re-key the stored selectors, or (c) carry the
entity type on the observation so the normaliser can disambiguate. (c) is
correct and the most work.

---

## 🔵 CONFIRM EXTERNALLY

Claims this build relies on that came from documentation or reasoning
rather than an authoritative source.

### C1 — Evidence authenticity standards

decision 13 targets **US FRE 902(13)–(14)** and **Canada Evidence Act
ss. 31.1–31.8**. The build produces SHA-256 and BLAKE3 per exhibit, a
hash-chained custody ledger and a report that identifies rather than
describes the record.

**Confirm:** that a hash-value certification in this form is acceptable to
the courts you will actually appear in, and what the certifying declaration
must say. This was reasoned from the rule text, not from a practitioner.

### C2 — MinIO COMPLIANCE object lock

The build uses COMPLIANCE mode, not GOVERNANCE, on the reasoning that
GOVERNANCE is bypassable by a principal holding
`BypassGovernanceRetention` — including the API's own credentials.

**Confirm:** the behaviour of your actual object store. This has been
verified against MinIO's documented semantics and a local MinIO, **not**
against AWS S3 or another vendor, and it matters because it is the
difference between WORM and a strongly-worded suggestion. Also confirm that
COMPLIANCE mode is compatible with D4's purge obligations — **it is not, in
general**, and that tension is real: an object under compliance lock cannot
be deleted before its retention expires *even to satisfy a deletion order*.

### C3 — Prohibited-content hash sets

No automated screening is built. The reasoning is that holding known-material
hash sets requires authorisation this deployment does not have.

**Confirm:** whether you are authorised to hold them, from which provider,
and under what conditions. If yes, the screening hook exists
(`samples.triage` records it as a gap with a reason) and is a small piece of
work.

### C4 — Tox nospam and the 64-hex public key

The build indexes the first 64 hex of a Tox ID because the trailing nospam
is user-rotatable. This is stated in docs/10 and is consistent with the Tox
protocol as documented.

**Confirm** against the protocol specification before relying on it for
attribution in a filing. The claim is load-bearing: index the wrong thing
and the same actor silently fails to correlate after rotating nospam.

### C5 — Platform durable identifiers

`comms.platform.durable_selector_type` encodes, per platform, which
identifier is stable: Telegram numeric ID not `@username`; Session ID is
itself an X25519 public key; Matrix MXID plus device keys; Signal ACI.

**Confirm** each against current platform documentation. These change.
Discord, Telegram and Matrix have all altered identifier semantics within
the last few years, and a stale mapping produces confident false
attribution — the failure mode docs/10 calls "the single biggest source of
false attribution in this domain".

### C6 — Archive password convention

`infected` as the ZIP password is the MalwareBazaar / VirusShare /
malware-traffic-analysis convention. The build states in the archive
comment that it provides **no confidentiality**.

**Confirm** that your recipients' tooling expects it, and that your own
mail gateway and EDR exclusions are configured, before relying on transfer
working.

### C7 — Rate limits and what a real shift looks like

Decision 43 sets login attempt limits generous enough for "two hundred
analysts behind one egress address signing on at 09:00". That number is an
assumption about deployment shape.

**Confirm** the real concurrency, the real egress topology (how many public
addresses), and whether a proxy sits in front — `NOCTORNAL_TRUSTED_PROXY_HOPS`
defaults to 0 and X-Forwarded-For is ignored until it is set.

### C8 — Redis is not shared with a cache

The rate limiter's keys carry TTLs and `infra/docker-compose.yml` runs
Redis with `allkeys-lru`, so under memory pressure rate-limit state is
evictable and an evicted meter is a reset meter.

**Confirm** the production deployment gives the limiter its own Redis
database or instance. This is a deployment fix, not a code one, and it is
the kind that gets missed.

### C9 — Sample origin split

Invariant 10 requires sample bytes to be served from a **separate origin**.
`samples.download()` refuses unless `NOCTORNAL_SAMPLE_ORIGIN` is configured
and the request arrived at it.

**Confirm** that the deployment actually provides a second origin with
different cookie scope and CSP — `app.internal/samples` is not a separate
origin from `app.internal`, and the runtime check cannot tell the
difference between a real origin split and a CNAME.

### C10 — Sanctions and blockchain data licensing

`SANCTIONS_LIST` and `BLOCKCHAIN_TX` are ingest categories. Several
commercial chain-analytics and sanctions feeds forbid redistribution or
derived-work publication.

**Confirm** the licence terms of each feed before its output reaches a
report that leaves the building through the egress gate.

---

### C11 — PGP verification as evidence, and the verifier it depended on

Added 2026-07-25 with `apps/api/src/noctornal_api/pgp.py`.

A `CONFIRMED` channel binding is the only grade this system says may carry
weight in automatic identity resolution, and a verified PGP signature is
the only thing that produces one. The build implements no cryptography: it
drives the `gpg` binary and parses only its `--status-fd` output. Every
verification row stores the verifier's version string and gpg's raw status
lines, so a disputed verification can be re-read rather than re-argued.

**Confirm** three things before a verification is offered as evidence:

1. **That the conclusion means what a court will take it to mean.** The
   build asserts a narrow thing — this key signed text containing this
   identifier — and refuses to assert control of the identifier by its
   holder, which is an inference on top. A filing should not widen it
   silently.
2. **Which gpg build was used, and whether it was current.** The version is
   recorded per verification for exactly this reason. A verification made
   with a build carrying a known signature-validation defect is not
   evidence of anything, and the recorded version is what lets you find
   those rows later.
3. **How the vendor's public key was obtained.** The build never fetches
   keys (`--no-auto-key-locate`, no keyserver) precisely because a key
   fetched mid-verification is a key somebody else chose, and an outbound
   connection from an evidence check is an operational leak. The
   provenance of the key is therefore a HUMAN step, and an unrecorded one
   weakens the whole chain.

The build deliberately has **no `TRUSTED` outcome**: GnuPG's web of trust
answers "do I trust this key's owner", which is a different question from
"did this key sign this text", and an investigator's own keyring trust has
no bearing on whether a vendor controls a key.

### C12 — The GLOBAL service stoplist holds identifiers of people who are
not subjects

Added 2026-07-25 with `comms.service_selector`.

The stoplist is how the build avoids attributing a forum's escrow agent to
a vendor (docs/10's "serious, and easy, error"). It is **GLOBAL by
default** and deliberately so: a forum's escrow belongs to the forum, and a
per-case list would mean every case rediscovers it by getting the
attribution wrong first.

The consequence is that it is a cross-case store of identifiers belonging
to people who are, by construction, **not the subject of any
investigation** — escrow agents, guarantors, forum administrators. Entries
are retired rather than deleted, so they persist beyond the case that
added them.

**Confirm** the lawful basis and retention position for that store
specifically. It is not covered by a case's own retention rule, because it
outlives the case on purpose, and the argument for holding it (it prevents
misattribution) is a good one that still has to be made rather than
assumed.

### C13 — Co-participation manufactures ties, including for third parties

Added 2026-07-25 with `apps/api/src/noctornal_api/coparticipation.py`.

The projection draws a tie between two people because they were in the
same conversation. `include_incidental` defaults to **off** so participants
flagged as third parties get no ties, and `include_unresolved` defaults to
**off** so a member list does not become a set of actors — but both are
switchable, and switching them draws relationship inferences about people
who are not subjects.

**Determine** whether an analyst may switch them, and whether a network
including incidental participants may leave the boundary at all. The
egress gate checks classification, not this flag, so a report built from a
projection with `include_incidental=true` carries third-party
relationship inferences under whatever TLP the conversations had.

## Things this build deliberately does NOT do

Recorded so their absence is not mistaken for an oversight.

| Not built | Why |
|---|---|
| Automated prohibited-content screening | C3 — needs an authorised hash set |
| Sandbox detonation | docs/11: integrate, do not build. The authorisation record exists; nothing submits |
| Victim notification | L2 — an obligation to determine, not a feature to add |
| Free-text search across victim PII | L2 — refused by design; the authorisation path is logged and narrow |
| Archive expansion in the sample pipeline | Uncapped is a zip bomb; capped is real work and is not done |
| Deep links with tokens in email | A bearer credential in the least trustworthy channel available |
| Any legal determination | This file is the inventory of them, not the answer to any |
