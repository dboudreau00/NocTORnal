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

### F2: `REJECTED` samples are destroyed, and that is the wrong default somewhere

**Built:** `samples.reject()` destroys the bytes and the data key, keeping the
row that says something was rejected and why.

**The problem:** in a jurisdiction that requires preservation of prohibited
material for a designated authority, destruction is itself an offence.
`reject(purge_bytes=False)` exists and nothing selects it automatically, so
the destructive path is the default in a system whose correct default is
jurisdictional.

**Decide with counsel before the first ingest.** docs/16 L1.

### F3: Six retention rules ship with placeholder periods

**Built:** migration 0032 seeds per-category retention, `STEALER_LOG` at 90
days, enforced independently of the case.

**The problem:** 90 days is a number somebody typed. Purge warns loudly on
every rule nobody has confirmed, which is the right behaviour and is not a
substitute for confirming them. The readiness register blocks a covert
collection pass while any rule is unconfirmed. docs/16 D3.

### F14: Which roles may invoke break-glass is a guess

Migration 0039 grants `break_glass.invoke` to `SYS_ADMIN` and `CASE_OWNER`.
That is the narrowest defensible default, not a recommendation: SYS_ADMIN
because operational emergencies are theirs, CASE_OWNER because the commonest
real case is the owner locked out of their own case at 3am. `ANALYST` was
deliberately excluded, because docs/05 wants break-glass available and
"available to everyone" is a different property.

**Decide:** who actually needs emergency access in your unit. Too tight and
people route around the system during an incident, which is worse than the
access; too broad and the review queue becomes noise nobody reads.

### F16: `victim_pii.reveal` is granted to no role

The permission exists, the endpoint is wired, and nothing holds it, so the
route refuses everyone. **Left ungranted deliberately:** who may decrypt a
victim credential is a docs/16 L2 decision, not a default this build should
pick.

When you grant it, `SECURITY_OFFICER` is the wrong holder. That role grants
the authorisation, and `grant_pii_authorisation` refuses
`granted_to == granted_by`, so giving it both collapses the two humans back
into one. The shape that works is a case role (`ANALYST` or `CASE_OWNER`)
holding `victim_pii.reveal` while `SECURITY_OFFICER` keeps
`victim_pii.authorise`. The reveal is then two people by construction, which
is the control docs/12 asks for.

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
