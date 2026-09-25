# 16. Legal and external dependency register

**Every place where this build has done as much as software can do, and the
rest is a decision somebody has to make outside it.**

Written because the alternative is worse: a system whose legal assumptions
live only in the heads of the people who wrote it ships, changes hands, and
then someone discovers the assumption by breaking it.

Three kinds of entry:

- 🔴 **BLOCKING**. Do not operate this in production until it is settled.
  The code may run; running it may not be lawful.
- 🟠 **DETERMINATION**, a policy choice the operator must make and write
  down. The software has picked a defensible default and will do whatever
  it is told instead.
- 🔵 **CONFIRM EXTERNALLY**, a factual claim this build relies on that
  came from documentation, convention or reasoning rather than from an
  authoritative source. Verify before depending on it.

Each entry says **what is built**, **what it assumes**, and **what must be
settled**. Nothing here is legal advice; it is an inventory of the places
where legal advice is required.

---

## 🔴 BLOCKING

### L1: Prohibited content in the sample store

**Built:** Phase 8 (`samples.py`, Alembic 0031). Ingest is refused until
`NOCTORNAL_PROHIBITED_CONTENT_POLICY` and `NOCTORNAL_DESIGNATED_PERSON` are
set. Since 2026-09-22 (docs/17 F2, decided by the owner) `REJECTED`
**preserves** by default: the encrypted bytes move into their own
object-locked store (`PRESERVE_BUCKET`) under a legal hold, the data key is
kept, and retrieving them takes two people (the Security Officer authorises,
the Lead investigator retrieves). It destroys the bytes and the data key only
where `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=destroy` is declared, and never
under a legal hold. The readiness check `prohibited_content_policy` states
which of the two this deployment does.

**Assumes:** that somebody has written the policy the environment variable
references. **The software records a declaration; it cannot verify one.** A
false declaration produces a working system and an unlawful deployment.

**Must be settled, with counsel, before the first ingest:**

1. Who is notified, how fast, through what channel, when screening trips.
2. What the `REJECTED` path does with the bytes, quarantine, secure
   destruction, or **preservation under legal instruction**. These
   conflict. The build now preserves unless told to destroy, which is the
   safer error (preserved material can still be destroyed later; destroyed
   material cannot be preserved), but it is not a legal answer: counsel
   decides which this jurisdiction requires, who the preserved material is
   held for, and for how long.
3. Reporting obligations in **both** operating jurisdictions (decision 13:
   US and Canada). They differ.
4. Who may see a quarantined item and under what authority.
5. Whether you are authorised to **hold** known-material hash sets at all.
   In most jurisdictions this requires specific authorisation. Screening is
   built (2026-09-24) and imports nothing until that authorisation is
   recorded in `NOCTORNAL_HASH_SET_AUTHORITY` as well as the ingest policy.
   See C3. A match isolates the sample for good, preserves its bytes under
   a legal hold, and alerts the Security Officer and the designated
   person; items 1 to 3 remain yours and counsel's.
6. How an analyst's exposure is limited, logged and supported.
7. Static triage (2026-09-24) decrypts and parses every sample after
   submission, and keeps its fuzzy hashes (imphash, Rich header, ssdeep,
   TLSH) on the sample's row. Whether the fuzzy hashes of a sample later
   rejected as prohibited material amount to holding a hash set of such
   material. The build leaves them on the row, as the SHA-256 already is,
   and screening keeps a matched sample out of every similarity answer. Triage never runs on a rejected sample and discards
   its findings when a rejection lands while it runs.

**Residual, static triage:** the analysis child is started without the
deployment's secrets, but on Linux it can read the environment of other
processes running as the same user, which hold them, and it shares its
container's network with the database. A parser exploit in a hostile
sample could therefore reach this deployment's secrets and its database
host. The readiness row `sample_static_analysis` reports both facts on the
host it runs on; a separate container with no secrets and no network is the
remedy, and is a deployment change.

Outbound lookups (roadmap F15, 2026-09-24) honour this entry too: a hash
that any sample holds is sent to a lookup provider, whatever subject kind
carries it (the sample itself, a selector or a typed value), only once
that sample has been screened with no match against every active list
(2026-09-25). A matched sample is never named: the lookup is refused with
the same sentence a restricted value gets. The sandbox reads the same rule
before it sends a sample to a target whose exposure is not NONE.

### L2: Stealer logs and third-party personal data at scale

**Built:** Phase 9 (`ingest.py`, Alembic 0033). Operator confirmed
2026-07-25 that stealer logs are in scope. Compartment enforced, victims as
`VICTIM` nodes flagged `is_incidental`, credential values masked by default
with a step-up reveal, per-category retention shorter than the case
default, free-text search across victim PII refused without a logged
authorisation.

**Assumes:** that holding this material has a lawful basis, and that the
basis extends to every victim in the archive, who are, by definition, not
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
   default and the reveal is step-up audited. Who reveals was decided by
   the owner on 2026-09-22 (docs/17 F16, migration 0062): the Lead
   investigator (`CASE_OWNER`), under an authorisation only the Security
   Officer grants, so a reveal is always two different people. That settles
   who presses the button, not whether the value may be held.
5. Cross-border transfer, if any partner or analyst is in a third country.
   Outbound lookups refuse personal data toward every provider (by type, by
   the shape of any span in the value, and social profile URLs) until a
   transfer authority is recorded; nothing in this build records one yet.
6. What "minimisation review at closure" must actually produce.

### L3: Persona operation and computer-misuse exposure

**Built:** Phase 4 (`collection.py`, persona vault). Credentials are
envelope-encrypted and decrypted only inside `PersonaVault.use()`, which
runs in the API process. There is no separate collector (invariant 7).

**Assumes nothing about authority.** The software will happily drive an
account into a forum. Whether *you* may is not a software question.

**Must be settled, with counsel:**

1. Authority to operate a covert persona against each target, per
   jurisdiction. In several, accessing a system using credentials
   registered under a false identity engages computer-misuse law
   regardless of intent.
2. Whether **passive collection** (reading a public forum) and **active
   collection** (posting, messaging, purchasing) are separately authorised.
   The build refuses every forum and Telegram read that no confirmed
   collection authority covers (recorded by one person, confirmed by
   another, scoped PUBLIC_READ or MEMBER_READ), and it has no active scope
   because nothing in it posts, messages or purchases. Until 2026-09-24
   this item said the build distinguished the two through an
   `ACTIVE_ENGAGEMENT` flag; no such flag ever existed, and a reader of an
   earlier copy of this register or of docs/18 A3 was told of a control
   that was not there. The authorisation itself is external.
3. Entrapment and agent-provocateur exposure for any active engagement.
4. Terms-of-service breach as an independent risk from criminal exposure.

A lookup provider's API account (roadmap F15) is overt and attributable to
the deployment: it is not a persona, holds no false identity, and its key
lives in its own vault (`ProviderVault`), not the persona vault.

### L4: Message content capture

**Built:** Phase 7 (`comms.py`, Alembic 0034), message-level capture per
decision 35.

**Must be settled, with counsel:**

1. **Interception law.** Capturing a conversation a persona is *party to*
   is legally distinct from capturing one it is not, and both differ by
   jurisdiction. `conversation.provenance_class` records which, and refuses
   to be null, so the distinction is at least always recorded, but the
   authority is external.
2. One-party vs two-party consent for the recording of communications.
3. Whether captured content of **uninvolved third parties** in a group
   channel is retainable, and for how long.

**Telegram (roadmap F5.3, 2026-09-24).** A Telegram chat's provenance
follows how it is read: OPEN_GROUP when the persona reads it without
joining, PERSONA_PARTY when it reads as a member. A member chat needs the
member scope of a collection authority, whose own member-access reference
is required, which is stricter than `comms._NEEDS_AUTHORITY`, where a
PERSONA_PARTY conversation needs none. A group chat's messages carry
thousands of uninvolved people's words and typed account ids: they are
collected documents under the CHAT_EXPORT retention rule, outside case
minimisation, and no route or script sweeps collected documents yet
(docs/17). Adding a chat by its id reads up to 500 entries of the persona's
own conversation list to find it; everything but the matched chat is
dropped in memory and never logged or stored. Media is never downloaded
(L1).

---

### L5: Active web capture of attacker infrastructure

**Built:** the deception subsystem (`deception.py`, Alembic 0048-0050),
per docs/19.

**Added to this register 2026-07-26, late.** It was written up in
docs/19 §6, README, SECURITY.md and ARCHITECTURE.md when the deception
work landed, and enforced in the schema the same day (but it was never
added *here*, and so it was also missing from the counsel pack in
docs/18, which carried A1 to A4 only). Every user-facing document said five
blocking items while the two documents a lawyer actually reads said four.
The drift ran in the dangerous direction: the review pack under-reported.
Recorded plainly because a register that quietly omits an item is worse
than no register.

Fetching a phishing page is an **outbound interaction with attacker
infrastructure**. Two distinct exposures:

**Must be settled, with counsel:**

1. **That fetching attacker infrastructure is authorised at all.** An
   attributable fetch discloses the investigation to the operator of the
   kit. The software half is a required egress profile for any non-passive
   capture method (`capture_active_needs_egress_profile`); whether the
   fetch may be made is not a software question.
2. **Submitting anything to the page is a different act entirely, and
   needs its own authority.** Entering credentials (*including canary or
   fabricated ones*) to observe what the kit does may constitute
   unauthorised access and may be an offence under computer-misuse
   statutes in several jurisdictions. `deception.capture` carries
   `submitted_input boolean` and the CHECK
   `capture_submission_needs_authority`, which refuses the row unless
   `submission_authority_ref` is present
   (`db/migrations/versions/0048_deception_capture.py:135`).
3. Whether a captured page containing **third-party victim data** (a
   credential-harvest page may render a targeted person's name or address) is retainable on the same terms as the rest of the case, or falls
   under L2's regime instead.

As with L1 in Phase 8: the software is built and refuses to operate the
gated part until a human records the authority. **That refusal is the
feature, not an unfinished edge**, and, exactly as with L1, it records a
declaration it cannot verify.

**No credential submission is automated.** There is a column to record
that a human did it under authority, and no code that does it.

**Key lookups (F10c, 2026-09-24).** A Web Key Directory lookup to a domain
the people under investigation run is an L5 interaction. The `wkd`
integration route must list providers only; adding any other domain needs
the L5 authority first. The build cannot tell a provider's domain from an
actor's, which is why the route takes named directories only and refuses a
wildcard.

---

## 🟠 DETERMINATION

### D1: Dual control on merge defaults to OFF

Decision 44. docs/05 scopes dual control to "the genuinely irreversible",
and a merge here is a reversible ledger. The operator may want it on for
particular cases, or as a standing rule. Per-case switch,
`PUT /cases/{id}/policy` (Triage, Dual control): one signature turns it on,
and turning it off takes a second Lead investigator on the case (F9b,
2026-09-24). Or as a standing rule: Administration, Two-person controls,
sets merges to need a second signature every time, which an administrator
proposes and a Security officer countersigns (F9, 2026-09-24).

### D2: Withheld-material disclosure defaults to PRESENCE

Decision 49 / migration 0030. An under-cleared analyst is told the picture
is incomplete but not by how much. `NONE` and `COUNT` are available per
case. **The honest limitation is written into the migration:** neither is
leak-proof against differencing, and the compensating control is that
every projection request is audited.

### D3: Retention periods

Per-case `retention_until` is mandatory and always has been. Phase 6 adds
**per-category** retention that can be shorter and is enforced
independently, `STEALER_LOG` at 90 days is a placeholder. Somebody has to
choose the real numbers, and they are jurisdictional.

Vendor keys, their user IDs and key lookups (F10b, F10c, 2026-09-24) are
kept with the case and are not yet on a retention clock. They are never
deleted by the application (their tables refuse it), so a legal hold is
never at odds with them; a future purge must overwrite their content under
the hold check rather than delete the rows.

### D4: Purge destroys or preserves

`retention.py` purges on expiry unless `legal_hold` is set. The
**tombstone** survives, what was destroyed, under what authority, by whom.
Whether the default should be destruction at all, versus offline archive,
is an operator decision with a legal input.

### D5: Detonation exposure

Decision 47. A non-private sandbox submission needs a named authoriser in a
DB constraint. **Which vendors count as "private"** is an operator
determination and depends on contracts this build has not seen. Several
"private" vendor tiers still share hashes with partners.

Since 2026-09-24 a self-hosted CAPEv2 can actually be sent to
(docs/11). Its exposure is the operator's declaration on the TARGET
(`NOCTORNAL_SANDBOX_EXPOSURE`, no default), recorded on every request
and re-checked before a send: a wrong declaration makes a disclosure look
private. The CAPE network route is a second exposure dimension (a live
route lets the sample reach its operators), and a live route, like an
exposed target, needs a second person's sign-off in the product. CAPE
keeps what it is sent outside this product's labels, holds and retention.

### D6: Ingest key holders

docs/12 open question 1. The build assumes keys may be held by external
partners: write-only scope is enforced by a CHECK constraint, IP allowlists
and mandatory expiry exist. If keys are internal-only, the abuse model is
smaller and some of that can relax. If external, a support and revocation
process is needed that the software does not provide.

### D7: Break-glass reviewer

`break_glass.py` requires a named security officer to review every
invocation. **Who that is** is an operator determination, and the build
will refuse to grant break-glass if no user holds
`SECURITY_OFFICER`, deliberately, because unreviewed emergency access is
just access. Which ROLES invoke and review was decided by the owner on
2026-09-22 (docs/17 F14): invoke with `CASE_OWNER` and `SYS_ADMIN`, review
with `SECURITY_OFFICER` only, and no role may hold both (migration 0062).

### D8: Telegram channel and user ids can share one durable value

> **✅ RESOLVED 2026-07-26 by option (b)+(c).** `telegram_id_norm` now
> namespaces every id, `u:` user, `c:` channel/supergroup, `g:` basic
> group, and **accepts an explicit prefix from a caller that knows the
> entity type**, which is option (c) for any collector able to supply it,
> with `u:` assumed otherwise. Migration
> `0051_telegram_norm_arithmetic.py` re-keys the stored selectors, and it
> re-derives from `raw_value` rather than rewriting `norm_value` in
> place, an earlier draft did the latter and would have stamped
> already-stripped channel ids as `u:`, recreating the exact collision it
> was removing. It carries a pre-flight that raises on a would-be
> collision rather than merging rows.
>
> The original text is kept below because the *reasoning* is still the
> record of why a normaliser cannot disambiguate alone.
>
> **2026-09-11:** the `u:` assumption for a bare positive is withdrawn.
> A bare positive now normalises to nothing and is refused with a note
> naming the typed forms; only `u:`/`c:`/`g:` is accepted. The rows typed
> by assumption between the two dates are listed by
> `scripts/telegram_bare_ids.py` (docs/17 F1).

Added 2026-07-25. **This was a known correctness defect that was
reported rather than fixed, and it needed a decision.**

`noctornal_ontology.telegram_id_norm` strips the Bot-API `-100` prefix so
that the two encodings of one supergroup collapse onto each other. Its own
docstring says a chat id and an unrelated user id "must never share a
norm_value", and stripping the prefix produces exactly that: the channel
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

### D9: Outbound lookup exposure

Added 2026-09-24 (roadmap F15). **Which lookup providers count as VENDOR or
PUBLIC is the operator's determination**, recorded per provider with a
written basis and the name of the administrator who made it. The build
cannot verify a VENDOR or PUBLIC claim: several vendor tiers share lookups
with partners, and a community service may publish them. Lowering a
provider's exposure (PUBLIC to VENDOR, or to NONE) takes a second
administrator, and the database refuses it otherwise.

NONE (your own instance) is the one level the code checks: its egress
route must name the private network it answers from, with no public entry
admitting the same host, and a direct send refuses an answer from outside
that network. **That proves the first hop only**; where the instance
forwards queries is not visible to this build.

Nothing is sent until a provider is registered and enabled, its route
exists, and the host operator has set `NOCTORNAL_OUTBOUND_LOOKUPS=on`. A
lookup to a VENDOR or PUBLIC provider is also signed off, in the product,
by a colleague the requester names (docs/00 decision 75); personal data and
sample hashes are refused outright (L1, L2).

**Determine:** the level of each provider you register, and whether any
outbound lookup at all needs counsel's sign-off first. If it does, this
entry moves to BLOCKING and the readiness row `outbound_lookup_providers`
becomes blocking.

### D10: Egress exit providers

Added 2026-09-24 (S2, the egress proxy). Persona traffic leaves through the
exit its egress profile names: a residential proxy pool, a VPN, Tor, or
this host's own address where that is allowed at all. Some residential
proxy networks route through devices whose owners did not knowingly
consent, and using one may be unlawful or unethical here. A profile records
the exit's kind and region only. The build seals each exit for the proxy
alone, and asks for an audited acknowledgement before a residential or VPN
exit is used in clear; it cannot tell a network whose device owners
consented from one whose did not, and it cannot tell whether a Tor exit's
use is acceptable to your authority.

**Determine,** with counsel: which exit providers may carry persona
traffic, whether Tor exits may, and on what terms. Relates to L3 (persona
operation) and L5 (fetching attacker infrastructure).

### D11: Egress ledger retention

Added 2026-09-24 (S2). `collect.egress_connection` records every connection
the egress proxy made or refused: the route, the destination (for a
persona route, the site of a source the deployment reads), the resolved
address, bytes and outcome. It is append-only and hash-chained, and **this
build never purges it**: no retention rule covers it, and a purge would
have to keep the chain verifiable.

**Determine:** how long the connection ledger is kept, and whether its
persona rows, which say what the deployment read and when, follow the
retention of the sources and cases they concern.

### D12: Case text sent to a model endpoint

Added 2026-09-24 (F6). Similar meaning sends case text (collected
documents, the titles and descriptions of exhibits, claims) to an
operator's model server to be embedded. **The default is none:** it is off
unless `NOCTORNAL_EMBED_MEANING_URL` is set, and similar wording, which runs
on this host and sends nothing, needs no determination. Any endpoint
outside this host, which in production is every endpoint, needs a written
authority in `NOCTORNAL_EMBED_MEANING_AUTHORITY`; it receives nothing above
its declared ceiling, nothing compartmented, no victim data, nothing from a
closed case, and no message text unless `NOCTORNAL_EMBED_MEANING_MESSAGE_AUTHORITY`
names the authority L4 requires. Every batch and query is audited before it
is sent. What the model server logs and keeps is outside this product's
labels, holds and retention.

**Determine:** whether any model server may receive case text at all, the
authority that covers it, its ceiling, whether message text may go (L4),
and what the server's operator logs and keeps.

---

## 🔵 CONFIRM EXTERNALLY

Claims this build relies on that came from documentation or reasoning
rather than an authoritative source.

### C1: Evidence authenticity standards

decision 13 targets **US FRE 902(13), (14)** and **Canada Evidence Act
ss. 31.1-31.8**. The build produces SHA-256 and BLAKE3 per exhibit, a
hash-chained custody ledger and a report that identifies rather than
describes the record.

**Confirm:** that a hash-value certification in this form is acceptable to
the courts you will actually appear in, and what the certifying declaration
must say. This was reasoned from the rule text, not from a practitioner.

### C2: MinIO COMPLIANCE object lock

The build uses COMPLIANCE mode, not GOVERNANCE, on the reasoning that
GOVERNANCE is bypassable by a principal holding
`BypassGovernanceRetention`, including the API's own credentials.

**Confirm:** the behaviour of your actual object store. This has been
verified against MinIO's documented semantics and a local MinIO, **not**
against AWS S3 or another vendor, and it matters because it is the
difference between WORM and a strongly-worded suggestion. Also confirm that
COMPLIANCE mode is compatible with D4's purge obligations, **it is not, in
general**, and that tension is real: an object under compliance lock cannot
be deleted before its retention expires *even to satisfy a deletion order*.

> **2026-09-16: the upstream is archived.** `https://dl.min.io` now answers
> 410 Gone with "The open-source MinIO Server, MinIO Client (mc) and MinIO
> KES projects are archived and no longer maintained. MinIO does not
> provide product support, security updates, or security advisories for
> them, and does not accept or process vulnerability reports concerning
> them." The Docker Hub images went with it; quay.io still serves the last
> community builds, which is what this tree now pins.
>
> That is a second question for the same reviewer, and a harder one. The
> WORM guarantee under every exhibit rests on software that will receive no
> security fix, and "the evidence store has a known unpatched
> vulnerability" is a disclosure answer nobody wants to give. It is not
> urgent in the sense of breaking anything today, and it does not become
> less true by waiting. See docs/17.

> **2026-09-22: decided by the owner (docs/17 F24).** Stay on the pinned
> community build, with the risk accepted in writing; the store is an
> internal, non-internet-facing service in the production compose, which
> bounds the exposure. And stop taking the store's word for it: the
> readiness register now **proves** write-once instead of reading the lock
> configuration. It keeps one canary object per bucket under a one-day
> COMPLIANCE retention and, on every probe, tries to DELETE that exact
> version id, passing only when the store refuses and the version survives
> (`evidence_bucket_object_lock`, and `preservation_bucket_object_lock` for
> the rejected-sample store). A refusal counts only from credentials that
> were allowed to delete: the preservation account is minted unable to, so
> that bucket is proven with the `MINIO_*` credentials on the same store,
> and the evidence says which credential made the proof.
>
> Why a configuration read was not evidence: SeaweedFS accepts a COMPLIANCE
> retention and has let the delete succeed anyway (seaweedfs issues 8350
> and 11333, the second deleting the locked version by its id), and Garage
> implements no object lock at all. Ceph RGW is maintained and implements
> S3 Object Lock in both modes, and is the self-hosted option if the pinned
> build has to be left. A vendor-operated S3 moves the evidence onto
> somebody else's infrastructure, which is a custody question for this
> register (who can reach the bytes, in which jurisdiction, under whose
> legal process) before it is a technical one.
>
> **Still to confirm externally,** whichever store is used: that a
> COMPLIANCE lock on it is the property your courts need, and that the
> probe passing on it is evidence enough of that for your disclosure
> regime. The probe shows the store refused one delete; it does not show
> that nothing else can remove an object, and whoever holds the volume can.

### C3: Prohibited-content hash sets

Screening is built (2026-09-24, docs/11) and holds nothing until you say
so. Holding known-material hash sets requires authorisation; the import is
refused until it is recorded in `NOCTORNAL_HASH_SET_AUTHORITY` (copied onto
each list, with the list's own licence reference). A list held in Postgres
is in every backup and dump, which a licence may forbid; retiring a list
and purging its entries removes them from the database, not from old
backups.

**Confirm:** whether you are authorised to hold them, from which provider,
and under what conditions, and whether your backups may carry them.
Screening compares exact hashes only: no match does not mean the material
is lawful to hold.

### C4: Tox nospam and the 64-hex public key

The build indexes the first 64 hex of a Tox ID because the trailing nospam
is user-rotatable. This is stated in docs/10 and is consistent with the Tox
protocol as documented.

**Confirm** against the protocol specification before relying on it for
attribution in a filing. The claim is load-bearing: index the wrong thing
and the same actor silently fails to correlate after rotating nospam.

### C5: Platform durable identifiers

`comms.platform.durable_selector_type` encodes, per platform, which
identifier is stable: Telegram numeric ID not `@username`; Session ID is
itself an X25519 public key; Matrix MXID plus device keys; Signal ACI.

**Confirm** each against current platform documentation. These change.
Discord, Telegram and Matrix have all altered identifier semantics within
the last few years, and a stale mapping produces confident false
attribution, the failure mode docs/10 calls "the single biggest source of
false attribution in this domain".

### C6: Archive password convention

`infected` as the ZIP password is the MalwareBazaar / VirusShare /
malware-traffic-analysis convention. The build states in the archive
comment that it provides **no confidentiality**.

**Confirm** that your recipients' tooling expects it, and that your own
mail gateway and EDR exclusions are configured, before relying on transfer
working.

### C7: Rate limits and what a real shift looks like

Decision 43 sets login attempt limits generous enough for "two hundred
analysts behind one egress address signing on at 09:00". That number is an
assumption about deployment shape.

**Confirm** the real concurrency, the real egress topology (how many public
addresses), and whether a proxy sits in front, `NOCTORNAL_TRUSTED_PROXY_HOPS`
defaults to 0 and X-Forwarded-For is ignored until it is set.

### C8: Redis is not shared with a cache

The rate limiter is the only user of `REDIS_URL`, and its meters are keys
with TTLs. Under an evicting `maxmemory-policy` (any `allkeys-*` or
`volatile-*`) memory pressure deletes live meters, and an evicted meter is
a reset meter: it admits the subject it was refusing with a full burst.
Both compose files run Redis with `noeviction`, so at the 1 GB cap it
refuses writes instead, and each limit falls back to its declared
`on_backend_failure`. The development file ran `allkeys-lru` until Alpha 6.
The readiness check `redis_limiter_store` reads the policy with `CONFIG
GET` and fails on an evicting one, or reports it as unknown where `CONFIG`
is disabled. `redis_limiter_isolated` counts the keys in the limiter's
database that are not under its `rl:` prefix, and the keys in the
instance's other databases, and fails on either; it reads no value and
reports no key name.

**Confirm** the production deployment gives the limiter its own Redis
instance, running `noeviction`: `maxmemory` is per instance, so a
co-tenant in another database fills the same memory. The check sees a
co-tenant only while it holds keys, and cannot see a second server behind
the same address. This is a deployment fix, not a code one, and it is the
kind that gets missed.

### C9: Sample origin split

Invariant 10 requires sample bytes to be served from a **separate origin**.
`samples.download()` refuses unless `NOCTORNAL_SAMPLE_ORIGIN` is configured,
is a real second origin rather than a second name for the application's
(`NOCTORNAL_BASE_URL`), and the process serving the request is configured
as that origin (`NOCTORNAL_PUBLIC_ORIGIN`) -- decided from configuration,
never from the request, since 2026-09-09. Unset means the split is OFF and
every download refuses; the readiness register says so.

**Confirm** that the deployment actually provides a second origin with
different cookie scope and CSP, `app.internal/samples` is not a separate
origin from `app.internal`, and the runtime check cannot tell the
difference between a real origin split and a CNAME.

### C10: Sanctions and blockchain data licensing

`SANCTIONS_LIST` and `BLOCKCHAIN_TX` are ingest categories. Several
commercial chain-analytics and sanctions feeds forbid redistribution or
derived-work publication.

**Confirm** the licence terms of each feed before its output reaches a
report that leaves the building through the egress gate.

---

### C11: PGP verification as evidence, and the verifier it depended on

Added 2026-07-25 with `apps/api/src/noctornal_api/pgp.py`.

A `CONFIRMED` channel binding is the only grade this system says may carry
weight in automatic identity resolution, and a verified PGP signature is
the only thing that produces one. The build implements no cryptography: it
drives the `gpg` binary and parses only its `--status-fd` output. Every
verification row stores the verifier's version string and gpg's raw status
lines, so a disputed verification can be re-read rather than re-argued.

**Confirm** three things before a verification is offered as evidence:

1. **That the conclusion means what a court will take it to mean.** The
   build asserts a narrow thing (this key signed text containing this
   identifier) and refuses to assert control of the identifier by its
   holder, which is an inference on top. A filing should not widen it
   silently. Since 2026-09-24 (F10a) a signature made by a signing SUBKEY
   is recorded as a signature by the primary key that subkey is bound
   under, and both fingerprints are on the row: vendors publish the
   primary and sign with a subkey. Since the same date (F10b) a binding is
   confirmed only when a cited contact block lists the signing key's
   fingerprint as its publisher's own and ties that publisher to the
   binding; otherwise the check is recorded as UNATTRIBUTED.
2. **Which gpg build was used, and whether it was current.** The version is
   recorded per verification for exactly this reason. A verification made
   with a build carrying a known signature-validation defect is not
   evidence of anything, and the recorded version is what lets you find
   those rows later. Since 2026-09-24 (F10a) a build below the floor is
   treated as no verifier at all (NO_VERIFIER): 2.4.9 in the 2.4 series,
   2.5.14 in the 2.5 series, 2.2.51 in the 2.2 series, and no 2.3. The
   floor carries the fixes for CVE-2022-34903 (a status-line injection
   that can forge a good signature) and CVE-2025-68973 (a memory error in
   the armour parser, which every path here feeds with armour an attacker
   chose). A distribution build that carries the fixes under an older
   version number counts only when the operator attests it by setting
   `NOCTORNAL_GPG_PATCHED_AS` to the upstream release it matches; the
   attestation is written on every verification row and shown in the
   `pgp_verifier` readiness row. Confirm that the operator's attestation
   is acceptable evidence of the build, or require a current upstream
   build.
3. **How the vendor's public key was obtained.** gpg never fetches keys
   itself (`--no-auto-key-locate`, no keyserver, no agent) because a key
   fetched mid-verification is a key somebody else chose, and an outbound
   connection from an evidence check is an operational leak. Since
   2026-09-24 (F10b) the build records each vendor key it is given: the
   bytes, where they were obtained, who added them, and who compared the
   fingerprint with the one the actor published, against which contact
   block line or which publication. It still does not decide who the actor
   is: whether the page the fingerprint was compared against is really the
   actor's remains a judgement, and it is recorded as one person's. A Web
   Key Directory lookup (F10c, C14) is the one way a key is fetched, off by
   default and approved by a second person.

The build deliberately has **no `TRUSTED` outcome**: GnuPG's web of trust
answers "do I trust this key's owner", which is a different question from
"did this key sign this text", and an investigator's own keyring trust has
no bearing on whether a vendor controls a key.

### C12: The GLOBAL service stoplist holds identifiers of people who are
not subjects

Added 2026-07-25 with `comms.service_selector`.

The stoplist is how the build avoids attributing a forum's escrow agent to
a vendor (docs/10's "serious, and easy, error"). It is **GLOBAL by
default** and deliberately so: a forum's escrow belongs to the forum, and a
per-case list would mean every case rediscovers it by getting the
attribution wrong first.

The consequence is that it is a cross-case store of identifiers belonging
to people who are, by construction, **not the subject of any
investigation**, escrow agents, guarantors, forum administrators. Entries
are retired rather than deleted, so they persist beyond the case that
added them.

**Confirm** the lawful basis and retention position for that store
specifically. It is not covered by a case's own retention rule, because it
outlives the case on purpose, and the argument for holding it (it prevents
misattribution) is a good one that still has to be made rather than
assumed.

### C13: Co-participation manufactures ties, including for third parties

Added 2026-07-25 with `apps/api/src/noctornal_api/coparticipation.py`.

The projection draws a tie between two people because they were in the
same conversation. `include_incidental` defaults to **off** so participants
flagged as third parties get no ties, and `include_unresolved` defaults to
**off** so a member list does not become a set of actors, but both are
switchable, and switching them draws relationship inferences about people
who are not subjects.

**Determine** whether an analyst may switch them, and whether a network
including incidental participants may leave the boundary at all. The
egress gate checks classification, not this flag, so a report built from a
projection with `include_incidental=true` carries third-party
relationship inferences under whatever TLP the conversations had.

Extended 2026-09-24 with `apps/api/src/noctornal_api/affiliation.py`: the
Analysis pane can project forums and wallets to entities, drawing a tie
between two people because they posted on the same forum or channel,
controlled the same wallet, or held wallets money moved between. POSTS_ON
has no incidental flag, so whom an analyst records as a poster decides who
can be tied, and no collector writes POSTS_ON: every poster is an
analyst's claim. The option is off by default and chosen per run; derived
ties are marked derived and inferred, never stored, never drawn on the
sociogram, and no report reads them (reports build their own projection).
Conversations are not projected this way; the Comms pane's co-participation
view above remains their projection, with its defaults.

**Determine** whether a derived tie between third parties may be relied on
in an analysis that is disclosed, and whether the per-run choice needs a
recorded justification like the two switches above.

### C14: Third-party YARA rule licensing

Carried from docs/18 C14 (2026-09-24, with F12). Rule sets are stored in
the deployment's database with the licence their source states. A version
flagged for review cannot be activated until the activating Security
Officer, who may not be the person who uploaded or adopted it, writes down
the clearance they rely on; it is kept on the activation and in the audit
chain. **The software records a clearance; it cannot give one.** Several
sources in `yara/sources.json` (signature-base, elastic-protections, the
community mixes) carry non-permissive or mixed terms. **Confirm** with
counsel before activating them in a commercial or shared deployment.
Storing the corpus is not redistribution, but a backup or export handed to
a partner carries it.

### C15: A key lookup tells the directory's operator which address was looked up

Added 2026-09-24 with the Web Key Directory lookups in
`apps/api/src/noctornal_api/pgp_keys.py` (F10c).

A lookup sends the hash of the address's local part to the directory for
its domain. The hash is reversible by an operator who knows its own users,
so the operator learns which address was looked up, when, and from which
address the request came. The build keeps lookups off unless
`NOCTORNAL_WKD_CEILING` is set and an administrator has created the
integration route `wkd` listing each directory by name; each lookup is
asked for by one person and approved and sent by another (docs/00 decision 115),
lapses after 24 hours, carries at most the ceiling's classification and no
compartment, and is recorded before anything is sent.

**Confirm externally** that the unit may make such requests, from which
address, and which directories may be listed on the route.

### C16: Lookup provider terms

Added 2026-09-24 (roadmap F15). Each provider's terms decide what this
build may do with its answers, and none has been read against them.

**Confirm**, for each provider before it is enabled: whether answers may
be cached and for how long (the per-case cache defaults to seven days);
whether commercial or investigative use is allowed at your tier (the
VirusTotal public API excludes commercial use); whether an answer may be
redistributed in a report that leaves through the egress gate; and what
filing an answer as a COMPLIANCE-locked exhibit does to the vendor's right
to ask for its deletion.

### C17: Jira Cloud residency, processing terms and audience

Added 2026-09-25 (roadmap F7). A Jira destination on `*.atlassian.net`
sends case codes (at SUBJECT and SUMMARY exposure) and one-line summaries
(at SUMMARY) to Atlassian's infrastructure, in Atlassian's jurisdiction,
into a project whose audience this build neither controls nor audits.
Nothing here collects, intercepts or captures, so this is not an L1 to L5
blocker; it is a disclosure to a processor.

**Confirm**, before a Cloud destination is activated: where Atlassian
holds the project's data and whether a data processing agreement covers
it; who can read the target project, today and as its permissions change;
that the field exposure chosen (STUB carries no case code) matches what
that audience may see; and that issues outlive this deployment's retention
and legal holds, since a purge here deletes nothing in Jira and the
operator closes or deletes them there by hand. A Data Center instance on
your own network raises the last two only.

### C18: Telegram behaviour the adapter relies on

Added 2026-09-24 (roadmap F5.3 and F5.4). The Telegram adapter is built on
behaviour Telegram documents loosely or not at all, and changes without
notice. Each is a place where being wrong is quiet.

**Confirm**, against Telegram's documentation and a test account, before
Telegram sources are read for a case: that message ids in a basic group
are per account (the adapter keys basic-group documents by the reading
account); that fetching a deleted message by id returns nothing (how a
deletion upstream is seen); that a public megagroup can be read without
joining; which acts show in a chat's recent actions log (joins, leaves)
and whether reading does; whether API reads move a persona's last-seen
time; the published data-centre network list and ports (the client and
the egress proxy refuse anything outside them, so a new range fails
closed); the terms for registering an api_id per persona from the
persona's own account; and whether reading a content-protected
(noforwards) chat through the API is within Telegram's terms.

### C19: The internal network has no route out

Added 2026-09-24 (S2, the egress proxy). The production deployment's claim
that the egress proxy is the only way out rests on a Docker network marked
internal. The readiness row `egress_boundary` checks the process, not the
host: it passes when the proxy accepted this process's key and refused a
private destination, and this process has no default route of its own.
Whether the network truly has no route out depends on the host, its Docker
version and its firewall, and Docker's embedded resolver forwards names it
cannot answer to the host's resolvers, so a name can still leave the host
as a lookup even though no connection can.

**Confirm externally,** once and after every Docker or firewall change,
with `docker network inspect` and the one-off connect in
`infra/production/README.md`, Egress, that the application network has no
route out, and decide whether the names that leave as lookups are
acceptable.

## Things this build deliberately does NOT do

Recorded so their absence is not mistaken for an oversight.

| Not built | Why |
|---|---|
| Perceptual matching of prohibited content | The exact-hash screening is built (C3); a perceptual matcher decodes hostile images and has no wheel for every supported platform |
| A sandbox of its own | docs/11: integrate, do not build. A self-hosted CAPEv2 can be sent to (D5); nothing else is |
| Victim notification | L2, an obligation to determine, not a feature to add |
| Free-text search across victim PII | L2, refused by design; the authorisation path is logged and narrow |
| Archive expansion in the sample pipeline | Uncapped is a zip bomb; capped is real work and is not done |
| Deep links with tokens in email | A bearer credential in the least trustworthy channel available |
| Vendor scans or submissions (VirusTotal, urlscan) | L5: the vendor would fetch attacker infrastructure for you. Lookups are report reads only |
| Inbound Jira status or comments | An unauthenticated receiver is a write primitive into the platform; Jira is never authoritative |
| Any legal determination | This file is the inventory of them, not the answer to any |
