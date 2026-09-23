# 17. Flagged for review: what was built that may need to change

"It passes its tests" and "it is right" are different claims, and the gap
between them is where this system does its damage. Everything below was built
deliberately, works as described, and rests on a judgement somebody other than
the author should confirm.

Three kinds of entry:

- 🔴 **CHANGE LIKELY.** A defect that is known, reported and not fixed, or a
  decision that is probably wrong for a real deployment.
- 🟠 **CONFIRM THE JUDGEMENT.** A defensible call that a different operator
  would reasonably make differently.
- 🔵 **ACCEPTED COST.** A deliberate trade with a known downside, recorded so
  nobody rediscovers it as a surprise.

For the legal dependencies see
[`docs/16-legal-and-external.md`](16-legal-and-external.md). This file is
about engineering judgement and does not repeat docs/16. Entries that have
been closed are listed at the end with the date and what closed them.

---

## Data already recorded that should not be trusted

If this instance has been used at all, these rows exist and are wrong. **This
is the section to act on first.**

| What | Affected rows | Why | What to do |
|---|---|---|---|
| **`CONFIRMED` channel bindings** created before commit `12ff904` | `comms.channel_binding` where `verification = 'CONFIRMED'` | The status parser could be fed a forged `VALIDSIG` line through a crafted OpenPGP user ID, minting a confirmation for a key the submitter did not hold. Also reachable with no signature at all, because `POST /bindings` accepted `verification: "CONFIRMED"` from the request body. | Re-derive each from its `comms.pgp_verification` row, or demote to `CLAIMED`. Do not accept the stored value. |
| **Co-participation figures** produced before commit `8595602` | Nothing persisted; the projection is computed live | Newman weighting divided by the filtered participant count, so a tie from a 500-member channel scored identically to a two-party DM. Any figure quoted in a report or a filing is wrong by up to the room size. | Recompute. Nothing to migrate. |
| **Contact-block attributions from Russian-language forums** parsed before `8595602` | `comms.contact_block_entry` where `role = 'SELF'` | The third-party label defence was ASCII-only, so `Гарант:` (guarantor) and `Эскроу:` (escrow) were read as the vendor's own. Any proposal raised from one is a misattribution of a forum service to a vendor. | Re-parse the affected blocks. `parser_version` on `comms.contact_block` identifies them. |
| **Durable values for Discord, ICQ, Signal, Wire, Wickr** written before `8595602` | `comms.channel_binding.durable_value` | Discord and ICQ handles without digits normalised to the empty string, which collides with every other such handle. Signal and Wire promoted phone numbers and handles their own platform seed says are not durable. | Repaired by migration 0038, recomputed from `observed_value`. Verify 0038 ran. |
| **Tox and Matrix durable values** written before commit `74a055d` | `comms.channel_binding.durable_value` | Repaired by migration 0036, which recomputes from `observed_value`. | Verify 0036 ran. |
| **Telegram ids recorded from a bare positive number** before 2026-09-11 | `core.selector` and `comms.channel_binding`, `TELEGRAM_ID` | A bare positive id was assumed to be a user (`u:`), so an MTProto channel observed as a bare number shares a row with a same-numbered user. The normaliser refuses a bare positive now, but nothing can recompute a type that was never observed. | `scripts/telegram_bare_ids.py` lists them per case. Confirm each against its source and re-record typed (`c:<id>`) where a channel is wearing a user's row. |

---

## 🔴 CHANGE LIKELY

Nothing is open here as of 2026-09-22. The owner decided F2, F14, F16 and
F24 that day, and F3 was reclassified as an accepted cost (it was never a
defect: the register already refuses on it). Each decision, and what was
built to hold it, is in the next section.

---

## Decided by the owner, 2026-09-22

The owner's instruction on the roles was "keep the split": `CASE_OWNER` is
the law-enforcement or threat investigator who controls their case, now
displayed as **Lead investigator** (the key is unchanged, so no permission
check moved), and `SECURITY_OFFICER` stays the independent overseer who
cannot read case content. F14 and F16 follow from that, and migration 0062
holds both.

### F2: a `REJECTED` sample is preserved, and destroyed only by declaration

**Was:** `samples.reject()` destroyed the bytes and the data key, keeping the
row. In a jurisdiction that requires preservation of prohibited material for
a designated authority, destruction is itself an offence, and the
destructive path was the default.

**Decided:** preserve by default. A rejected sample's encrypted bytes move
into their own store (`PRESERVE_BUCKET`, default `noctornal-preserved`, a
bucket created with object lock) under a legal hold on that object version,
and the data key is kept. Retrieving one is a two-person act, the same shape
as the victim-PII reveal: `sample.preserved.authorise` is the Security
Officer's alone and `sample.preserved.retrieve` the Lead investigator's, and
the pair is in `iam.separated_duty` so no role can be given both. Destruction
happens only where the deployment declares
`NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=destroy`, and never under a legal
hold, which refuses it. docs/11 has the mechanism.

**What the register says about it.** `prohibited_content_policy` (docs/16
L1) now states the disposition in its evidence: preserved into which bucket,
or destroyed. `preservation_bucket_object_lock` proves that bucket is
write-once the way F24 below describes, and fails by name on a disposition
that is neither value. What stays with counsel is unchanged: whether this
jurisdiction wants preservation at all, and for whom. docs/16 L1.

### F14: break-glass holders

**Was:** a guess. Migration 0039 granted `break_glass.invoke` to `SYS_ADMIN`
and `CASE_OWNER` as the narrowest defensible default.

**Decided:** exactly that. `break_glass.invoke` stays with `CASE_OWNER` and
`SYS_ADMIN` (operational emergencies are the administrator's, and the
commonest real case is the Lead investigator locked out of their own case at
3am); `break_glass.review` stays with `SECURITY_OFFICER` only. `ANALYST` stays
excluded, because "available to everyone" is a different property from
"available". Migration 0062 puts invoke and review in `iam.separated_duty`,
so a later grant cannot let a role review its own emergencies.

### F16: victim PII is two people by construction

**Was:** `victim_pii.reveal` was granted to no role, so the reveal route
refused everyone, while `victim_pii.authorise` was held by both
`SECURITY_OFFICER` and `CASE_OWNER`.

**Decided and built (migration 0062):** `CASE_OWNER` holds
`victim_pii.reveal` and no longer holds `victim_pii.authorise`, so
authorising is the Security Officer's alone. The reveal is two different
people by construction: the case gate reads the permission off the caller's
one role on the case, so a Lead investigator on their own case can reveal and
cannot authorise, and an officer assigned to the case as `SECURITY_OFFICER`
can authorise and cannot reveal (and reads no case content). Even the
first-run operator, who holds both roles globally, cannot authorise their own
reveal. `iam.separated_duty` refuses any grant that would give one role both
halves, and the upgrade refuses to install the guard over a role that
already has them. The lawful basis for holding the data at all is still docs/16 L2,
which no grant settles.

**The transition.** Before 0062 a Lead investigator could authorise a
co-lead on the same case for up to 30 days; that row opened nothing while
nobody held `reveal`, and after 0062 the co-lead holds it and the lookup
never asks who granted the row. So the upgrade revokes every live
authorisation whose grantor holds no role on the case that may authorise
today, and writes an audit event for each (`PII_AUTHORISATION_REVOKED`,
actor kind SYSTEM, naming both people and the migration). Authorisations a
Security Officer granted stand, because correlation has always been able to
use them. A downgrade does not restore the revoked ones: the revocation
happened, and nobody re-granted them.

### F24: the evidence store's upstream is archived

**Found 2026-09-16,** by a CI failure on a commit that changed only
documentation. `https://dl.min.io` answers 410 Gone: the open-source MinIO
server, client and KES are archived, unmaintained, and outside security
support, with vulnerability reports not accepted. quay.io still serves the
last community builds, and the CI step and both compose files pin those.

**Decided: stay on the pinned build, with the risk accepted in writing** (by
the owner, 2026-09-22, recorded here). The exposure is bounded by the store
being an internal, non-internet-facing service in the production compose.
The acceptance comes with one change: the readiness register no longer
**reads** the bucket's lock configuration, it **proves** write-once.

Why a configuration read was not evidence, from the research behind the
decision:

- **SeaweedFS** accepts a COMPLIANCE retention and has let the delete succeed
  anyway. Issue 8350 (February 2026, SeaweedFS 4.12, closed as not planned)
  reported a delete before the retain-until date succeeding by writing a
  delete marker; issue 11333 (September 2026) reported a DELETE naming the
  locked version's id succeeding before `RetainUntilDate`. A store in that
  state answers a lock-configuration read exactly as MinIO does.
- **Garage** implements no S3 object lock at all (its S3 compatibility
  reference; feature request 1127 on its own forge).
- **Ceph RGW** is maintained and implements S3 Object Lock in GOVERNANCE and
  COMPLIANCE modes. It is the self-hosted option if the pinned build has to
  be left, and a storage-adapter change rather than a model change, because
  `EvidenceStorage` already speaks S3.
- **A vendor-operated S3** (AWS S3 Object Lock and its peers) changes where
  the evidence physically sits and who can reach it, so it is a custody
  question for docs/16 C2 before it is a technical one.

**What the probe does** (`readiness.prove_write_once`). One canary object
per bucket at a fixed key (`.noctornal-worm-canary`), written with a one-day
COMPLIANCE retention only when it is absent or about to lapse; every probe
then issues a DELETE of **that version id** and passes only when the store
refuses it for retention and the version is still there. The version id is
the test: on a versioned bucket a DELETE without one adds a delete marker and
succeeds, which proves nothing (8350 above reads exactly like that). It runs
against the evidence bucket (`evidence_bucket_object_lock`) and the
preservation bucket (`preservation_bucket_object_lock`), with the register's
usual short timeouts and a ten-second budget for each check's whole proof.
Canary versions whose day has passed are removed by the next probe that
succeeds, so each bucket carries one or two, not one per day for ever. That
tidy is best effort: any failure in it, a dropped connection included, is
noted beside a proof that stands and never turns the row red.

**The mode is read, not assumed** (final review C10, 2026-09-23). A plain
DELETE is refused under GOVERNANCE exactly as under COMPLIANCE, and
GOVERNANCE yields to anyone holding the bypass permission, the root
credential included. So after writing a canary the probe reads back the
retention the store recorded, and a canary carrying any mode but COMPLIANCE
fails the check by name; it is not replaced, because on a store that
downgrades every replacement would be one more version locked for the
bucket's default period. Credentials that may not read a retention still
get a verdict from the refused DELETE, and the evidence then says COMPLIANCE
was requested and not confirmed.

**Each bucket is proven for the lock it relies on.** An exhibit carries a
COMPLIANCE retention, so the evidence bucket gets the proof above. A
preserved sample carries a **legal hold and no retention** (F2), and a hold
is a separate S3 mechanism: its own header, its own API, and an enforcement
path a store can get wrong while getting retention right. Until the final
review (C9, 2026-09-23) the preservation check proved only a retention and
said it proved the hold. It now also proves the hold
(`readiness._prove_hold`): a second canary at `.noctornal-hold-canary`,
written the way a rejected sample is written (hold in the PUT, then read back
as ON) by the account rejections are preserved with, then a DELETE of that
version id that must be refused with the version still there afterwards.
Both proofs must pass. A hold has no expiry, so that one held version is kept
for good and never tidied; if its hold is ever lifted by hand, the next
probe writes a fresh held one. On the pinned MinIO a held version is refused
with the same answer as a locked one ("Object is WORM protected"), measured
against the dev store on 2026-09-23. Whatever store this deployment moves
to, both checks must pass on it before an exhibit or a rejected sample is
written there.

**A refusal only counts from credentials allowed to delete.** An
`AccessDenied` is the account's policy, not the lock, so it never passes.
The preservation account in the production compose is minted unable to
delete or set a retention, on purpose, so its attempt always ends there;
the check then makes the proof with the `MINIO_*` credentials when they
address the same store, and says so in the evidence. It fails, and says the
proof cannot be made from this process, when no credential here may delete
on that store, and it fails without trying anything else when the account
rejections are written with cannot even read the bucket, because then every
rejection is refused. Both paths were run against the dev MinIO on
2026-09-23 with throwaway accounts carrying the production policies. The
hold proof keeps the same line: the held PUT and the read-back are always
the preservation account's, because they are the steps every rejection
takes, and only its DELETE moves to the `MINIO_*` credentials.

**Reopen** if a vulnerability is published against the pinned build that is
reachable from inside the deployment's network, or if the store is ever
exposed beyond it.

---

## 🟠 CONFIRM THE JUDGEMENT

### F4: The parser refuses far more than it extracts

`local@domain` is not resolved without a label (a JID and an email are the
same shape), bare 40-hex is not (SHA-1 is identical), bare 64-hex is not (Tox
pubkey, SHA-256 and OMEMO all match). Each refusal is stored as `UNPARSED`
with its reason, never dropped.

**The trade:** lower recall, and an analyst must label ambiguous lines by
hand. A confident wrong attribution is never revisited because nobody knows to
look, while a refusal is one click from correction. If your analysts find the
labelling burden too high this is the knob, but raise it by adding label
aliases, not by lowering the shape rules.

### F5: A signed payload must name the identifier, matched strictly

Confirmation requires the identifier to appear in gpg's own output of the
signed region, at a token boundary, at least four characters long. A genuine
signature can therefore land on `VALUE_NOT_IN_PAYLOAD` when the actor printed
the identifier in a different form, spaced hex for instance.

**The trade:** false negatives that cost an analyst a second look, chosen over
false confirmations. Loose matching was deliberately not implemented. Confirm
this is the right side to err on for your evidential standard.

### F6: The service stoplist is global, and holds identifiers of people who are not subjects

A forum's escrow agent belongs to the forum, so a per-case list would mean
every case rediscovers it by getting the attribution wrong first. The
consequence is a cross-case store of identifiers belonging to escrow agents,
guarantors and administrators who are, by construction, not under
investigation, and entries are retired rather than deleted, so they outlive
the case that added them. docs/16 C12.

### F7: Co-participation defaults exclude more than they include

Incidental participants and unresolved handles both get no ties by default.
Both are switchable, and switching them draws relationship inferences about
people who are not subjects. The egress gate checks classification, not this
flag. docs/16 C13.

### F8: Break-glass refuses to grant when no security officer exists

Deliberate: unreviewed emergency access is just access. In a small team this
may mean one person wearing both hats, which defeats the separation. Decide
whether to enforce it or accept the risk explicitly, rather than discovering
the gap in an audit. docs/16 D7.

### F21: The live websocket has no double-submit, by construction

`_handshake` authenticates from `__Host-session` off the upgrade, which is
what let login stop returning a token at all: the one credential surviving a
reload had been the one credential the live channel would not take.

A cookie-derived credential elsewhere in this codebase is accepted on an
unsafe method only alongside the `x-csrf-token` header `deps.session_token`
demands. That defence is unavailable here, because a browser cannot set a
header on a websocket upgrade. Two things stand in its place: `SameSite=Strict`,
which stops the cookie travelling on a cross-site upgrade, and an explicit
`Origin` check refused before `accept()`, so a flood spends no budget.

**Confirm the judgement:** those two are not belt and braces. SameSite is
scoped to the registrable domain, so a subdomain this deployment does not
control is inside it, and the `Origin` check is what stands there alone.

---

## 🔵 ACCEPTED COST

### F3: Six retention rules ship with placeholder periods, and collection waits for them

**Reclassified 2026-09-22** out of CHANGE LIKELY, because it was never a
defect. Migration 0032 seeds per-category retention (`STEALER_LOG` at 90
days) with periods somebody typed, and they are a deployment setting: the
right numbers are jurisdictional and no build can choose them. What the
build does is refuse to pretend otherwise. Purge warns on every rule nobody
has confirmed, and `retention_rules_confirmed` is one of the four
**blocking** readiness checks, so a collection poll is refused until a named
human has confirmed each period with a rationale.

**The cost:** a fresh deployment collects nothing until somebody confirms six
numbers. That is the intended cost of a placeholder that cannot quietly
become policy. docs/16 D3.

### F9: No cryptography is implemented, and gpg is a hard dependency

Verification shells out to the `gpg` binary and parses only its `--status-fd`
output. If gpg is absent the outcome is `NO_VERIFIER` and nothing is
confirmed: there is no path where a missing verifier produces a confirmation.
The cost is an external binary in the trust chain and a version-dependent
status format. The version is recorded on every verification row, so rows made
with a defective build can be found later.

### F10: Machines propose and never write the graph

The contact-block parser holds no `GraphWriteService`. Every finding becomes a
`collect.proposal` needing a human `reviewed_by`. The cost is that nothing
extracts automatically and the triage queue is the bottleneck. This is
invariant 3 and is not negotiable without changing the model.

### F11: Co-participation is a projection, never stored edges

Recomputed on every request, so it costs CPU rather than storage and can never
drift from its inputs. Writing it as edges would make a derived tie
indistinguishable from an observed one after the first person forgets, which
is what invariant 4 exists to prevent.

### F12: Rooms above `max_room_size` are excluded, and each is named

Newman weighting fixes a large room's influence; it does not fix the
combinatorial cost, and a 5,000-member channel still yields 12.5M near-zero
pairs. The cap is real data loss, so every excluded room is reported with both
its true size and how many participants were projectable. A cap that drops
data silently is worse than no cap, because the output looks complete.

### F13: CI has no typecheck

Decision 42. There are no annotations to check against, and adding them is a
large, low-yield change to a codebase whose invariants are enforced by
database constraints rather than by types.

### F22: What the Lab download ticket costs

The download is cross-origin by design, so no `__Host-` cookie can reach it
and nothing HttpOnly can cross. It crosses on a one-shot ticket minted on the
application origin under the cookie session (migration 0061), and that ticket
is legible to any script on the page, as the session token was until Wave 2.
The difference is what a lift is worth: one sample, one redemption, sixty
seconds, against the case file for twelve hours.

Before a byte moves, the redemption re-derives that the ticket is live, unspent
and issued for that sample; that the holder's account is still active and still
holds `sample.download` through a global role; and that the sample's labels
still compose against the holder's live clearance and compartments.

**Two residuals, stated in the code rather than closed.** A ticket minted under
a session revoked inside the following sixty seconds can still be redeemed, by
a holder whose account is still active and still permitted, for a sample they
may still read; the session is the one thing left because it is the one this
origin cannot answer without a third copy of a check `deps.py` keeps in two
places, on the very process the split exists to keep sessions away from. And
nothing sweeps spent ticket rows yet, though the partial index the sweep wants
exists.

---

## Deferred security items

Not defects, not done. Listed so they are not mistaken for oversights.

| Item | Consequence today |
|---|---|
| Session binding enforcement | Every session records the address and client it was minted from (0058) and `NOCTORNAL_SESSION_STRICT_BINDING=1` refuses a mismatch with an audit row. The production compose sets it; it is off by default everywhere else, so until an operator sets it a stolen token is portable |
| RLS under the non-owner role | The production deployment connects as `noctornal_app`, which is not the table owner and cannot disable the append-only triggers. Row-level security on top of that is not written, so a SQL injection inside a request still reaches every row the API can |
| Real SSRF protection | `collection.fetch()` blocks non-HTTP schemes and private literals and re-validates every redirect hop; DNS rebinding is not addressed, because the name is resolved once here and again by the socket layer |
| Compartment rename and removal | The registry is done: `iam.compartment` is the closed vocabulary (0057) and every compartment column is bound to it by trigger (0059), so a typo is refused and named. What is missing is a product route to rename or drop a registered key; the database refuses either while any row carries it, so today it is a manual per-column operation |
| WebAuthn | TOTP only. A deliberate absence, stated in four documents; SECURITY.md says reporting it is not a finding |

---

## Closed

Kept as an index, because the value of this register is that a reader can tell
a judgement nobody has confirmed from one that somebody has. The reasoning
behind each closure is in `release/CHANGELOG.md` under its date.

| | What it was | Closed |
|---|---|---|
| **F2** | `REJECTED` samples were destroyed by default | 2026-09-22, decided by the owner: preserved under a legal hold in their own object-locked store, two people to retrieve, destroyed only by declaration and never under a hold (section above) |
| **F14** | Which roles may invoke break-glass was a guess | 2026-09-22, decided by the owner: invoke with CASE_OWNER and SYS_ADMIN, review with SECURITY_OFFICER only; migration 0062 keeps the two apart |
| **F16** | `victim_pii.reveal` was granted to no role | 2026-09-22, decided by the owner, migration 0062: the Lead investigator reveals, the Security Officer alone authorises |
| **F24** | The evidence store's upstream is archived | 2026-09-22, decided by the owner: stay on the pinned build, risk accepted in writing, and the register now proves write-once instead of reading it (section above) |
| **F1** | A Telegram channel id and a user id could share one durable value | 2026-07-26, migration 0051: ids are namespaced `u:`/`c:`/`g:` and the Bot-API encoding is decoded arithmetically. The residual (a bare positive assumed to be a user) closed 2026-09-11: it is refused now, and `refusal()` names the typed forms. Rows written under the assumption are in the untrusted-data table above |
| **F15** | Ten Phase 4 and Phase 9 service defects, found by an adversarial pass | 2026-07-25, all fixed at the service |
| **F17** | The third adversarial pass: PGP status injection, the "encrypted" ZIP that was a plain ZIP, sample download with no label check | 2026-07-25. The rows those defects wrote are in the untrusted-data table above |
| Approvals UI | Phase 6 dual control had no analyst surface, so Merge was unreachable from a browser whenever it was on | 2026-08-10, Triage → Dual control |
| **F19** | Phases 5 and 8, the two that had never had a hostile pass: nine criticals, including a notification centre that never checked case assignment | 2026-07-26 |
| **F20** | The ACH matrix ranked an untested hypothesis top, and the warning that would have caught it could not fire | 2026-07-26 |
| Key ring | A mismatched `NOCTORNAL_TOTP_KEK` made login answer 500, and the readiness check could not see it, because it verified the key decoded and not that it decrypted anything | 2026-09-11: `key_id` selects the key, the register opens stored secrets and counts, and login refuses with a named 503 |

---

## How to keep this file honest

Add an entry when you build something whose correctness rests on a judgement
rather than on a test. Move one to the table above when the judgement is
confirmed by somebody who can carry it, and record who, in
`docs/00-decisions.md`.

The failure mode this file prevents is the one docs/16 names: a system whose
assumptions live only in the heads of the people who wrote it ships, changes
hands, and then somebody discovers an assumption by breaking it.
