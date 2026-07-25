# 17 — Flagged for review: what was built that may need to change

**Written 2026-07-25, at the end of the Phase 7 session.**

This file exists because "it passes its tests" and "it is right" are
different claims, and the gap between them is where this system does its
damage. Everything below was **built deliberately**, works as described,
and rests on a judgement somebody other than the author should confirm.

Three kinds of entry:

- 🔴 **CHANGE LIKELY** — a defect that is known, reported and not fixed,
  or a decision that is probably wrong for a real deployment.
- 🟠 **CONFIRM THE JUDGEMENT** — a defensible call that a different
  operator would reasonably make differently.
- 🔵 **ACCEPTED COST** — a deliberate trade with a known downside,
  recorded so nobody rediscovers it as a surprise.

For the *legal* dependencies see
[`docs/16-legal-and-external.md`](16-legal-and-external.md). This file is
about **engineering judgement**. It does not repeat docs/16.

---

## Data already recorded that should not be trusted

If this instance has been used at all, these rows exist and are wrong.
**This is the section to act on first.**

| What | Affected rows | Why | What to do |
|---|---|---|---|
| **`CONFIRMED` channel bindings** created before commit `12ff904` | `comms.channel_binding` where `verification = 'CONFIRMED'` | The status parser could be fed a forged `VALIDSIG` line through a crafted OpenPGP user ID, minting a confirmation for a key the submitter did not hold. Also reachable without any signature at all, because `POST /bindings` accepted `verification: "CONFIRMED"` from the request body. | Re-derive each from its `comms.pgp_verification` row, or demote to `CLAIMED`. Do not accept the stored value. |
| **Co-participation figures** produced before commit `8595602` | Nothing persisted — the projection is computed live | Newman weighting divided by the *filtered* participant count, so a tie from a 500-member channel scored identically to a two-party DM. Any figure quoted in a report or a filing is wrong by up to the room size. | Recompute. Nothing to migrate. |
| **Contact-block attributions from Russian-language forums** parsed before `8595602` | `comms.contact_block_entry` where `role = 'SELF'` | The third-party label defence was ASCII-only, so `Гарант:` (guarantor) and `Эскроу:` (escrow) were read as the vendor's own. Any proposal raised from one is a misattribution of a forum service to a vendor. | Re-parse the affected blocks. `parser_version` on `comms.contact_block` identifies them. |
| **Durable values for Discord, ICQ, Signal, Wire, Wickr** written before `8595602` | `comms.channel_binding.durable_value` | Discord and ICQ handles without digits normalised to the empty string, which **collides with every other such handle**. Signal and Wire promoted phone numbers and handles their own platform seed says are not durable. | Re-normalise from `observed_value`, as migration 0036 did for Tox/Matrix/Telegram. A migration for this is **not written**. |
| **Tox and Matrix durable values** written before commit `74a055d` | `comms.channel_binding.durable_value` | Repaired by migration **0036**, which recomputes from `observed_value`. | Already handled. Verify 0036 ran. |

---

## 🔴 CHANGE LIKELY

### F1 — A Telegram channel id and a user id can share one durable value

**Built:** `noctornal_ontology.telegram_id_norm` strips the Bot-API `-100`
prefix so the two encodings of one supergroup collapse together.

**The defect:** its own docstring says a chat id and an unrelated user id
"must never share a norm_value", and stripping the prefix produces exactly
that. Channel `-1001234567890` and **user** `1234567890` both normalise to
`1234567890`. Correlating on that value reports two unrelated entities as
one actor — the failure docs/10 calls the single biggest source of false
attribution in this domain.

**Why it was not fixed:** namespacing channel ids re-keys every stored
`TELEGRAM_ID` selector across `core.selector` and
`comms.channel_binding`, and it cannot be done correctly by the normaliser
alone — a bare positive number is a user in one encoding and a channel in
another, and only the collector that observed it knows which. The correct
fix carries the entity type on the observation, which is a model change.

**Interim control:** `comms.normalise` returns a WARNING naming the
collision on every affected observation, so it is visible at the point of
use rather than discovered in a conclusion.

**Decide:** accept with the warning / namespace and re-key / carry the
entity type. Recorded as **docs/16 D8**.

### F2 — `REJECTED` samples are destroyed, and that is the wrong default
somewhere

**Built:** `samples.reject()` destroys the bytes and the data key, keeping
the row that says something was rejected and why.

**The problem:** in a jurisdiction that requires preservation of
prohibited material for a designated authority, destruction is itself an
offence. `reject(purge_bytes=False)` exists and **nothing selects it
automatically**, so the destructive path is the default in a system whose
correct default is jurisdictional.

**Decide with counsel before the first ingest.** docs/16 L1.

### F3 — Six retention rules ship with placeholder periods

**Built:** migration 0032 seeds per-category retention, `STEALER_LOG` at
90 days, enforced independently of the case.

**The problem:** 90 days is a number somebody typed. Purge warns loudly on
every rule nobody has confirmed, which is the right behaviour and is not a
substitute for confirming them. docs/16 D3.

---

## 🟠 CONFIRM THE JUDGEMENT

### F4 — The parser refuses far more than it extracts

`local@domain` is not resolved without a label (a JID and an email are the
same shape), bare 40-hex is not (SHA-1 is identical), bare 64-hex is not
(Tox pubkey, SHA-256 and OMEMO all match). Each refusal is stored as
`UNPARSED` **with its reason**, never dropped.

**The trade:** lower recall, and an analyst must label ambiguous lines by
hand. The reasoning is that a confident wrong attribution is never
revisited because nobody knows to look, while a refusal is one click from
correction. **If your analysts find the labelling burden too high, this is
the knob** — but raise it by adding label aliases, not by lowering the
shape rules.

### F5 — A signed payload must NAME the identifier, matched strictly

Confirmation requires the identifier to appear in gpg's own output of the
signed region, at a token boundary, and at least 4 characters long. A
genuine signature can therefore land on `VALUE_NOT_IN_PAYLOAD` when the
actor printed the identifier in a different form — spaced hex, for
instance.

**The trade:** false negatives that cost an analyst a second look, chosen
over false confirmations. Loose matching was deliberately not implemented.
**Confirm this is the right side to err on for your evidential standard.**

### F6 — The service stoplist is GLOBAL, and holds identifiers of people
who are not subjects

A forum's escrow agent belongs to the forum, so a per-case list would mean
every case rediscovers it by getting the attribution wrong first. The
consequence is a cross-case store of identifiers belonging to escrow
agents, guarantors and administrators who are, by construction, **not
under investigation** — and entries are retired rather than deleted, so
they outlive the case that added them. docs/16 C12.

### F7 — Co-participation defaults exclude more than they include

Incidental participants and unresolved handles both get no ties by
default. Both are switchable, and switching them draws relationship
inferences about people who are not subjects. The egress gate checks
classification, **not this flag**. docs/16 C13.

### F8 — Break-glass refuses to grant when no security officer exists

Deliberate: unreviewed emergency access is just access. In a small team
this may mean one person wearing both hats, which defeats the separation.
**Decide whether to enforce it or accept the risk explicitly**, rather
than discovering the gap in an audit. docs/16 D7.

---

## 🔵 ACCEPTED COST

### F9 — No cryptography is implemented, and gpg is a hard dependency

Verification shells out to the `gpg` binary and parses only its
`--status-fd` output. If gpg is absent the outcome is `NO_VERIFIER` and
nothing is confirmed — there is no code path where a missing verifier
produces a confirmation. The cost is an external binary in the trust
chain, and a version-dependent status format. **The version is recorded on
every verification row** so rows made with a defective build can be found
later.

### F10 — Machines propose and never write the graph

The contact-block parser holds no `GraphWriteService`. Every finding
becomes a `collect.proposal` needing a human `reviewed_by`. The cost is
that nothing extracts automatically and the triage queue is the
bottleneck. This is invariant 3 and is not negotiable without changing the
model.

### F11 — Co-participation is a projection, never stored edges

Recomputed on every request, so it costs CPU rather than storage and can
never drift from its inputs. Writing it as edges would make a derived tie
indistinguishable from an observed one after the first person forgets —
which is what invariant 4 exists to prevent.

### F12 — Rooms above `max_room_size` are excluded, and each is named

Newman weighting fixes a large room's *influence*; it does not fix the
*combinatorial* cost, and a 5,000-member channel still yields 12.5M
near-zero pairs. The cap is real data loss, so every excluded room is
reported with both its true size and how many participants were
projectable. A cap that drops data silently is worse than no cap, because
the output looks complete.

### F13 — CI has no typecheck

Decision 42. There are no annotations to check against. Adding them is a
large, low-yield change to a codebase whose invariants are enforced by
database constraints rather than by types.

---

## Deferred security items

Not defects, not done. Listed so they are not mistaken for oversights.

| Item | Consequence today |
|---|---|
| Session IP/UA binding | A stolen token is portable |
| Non-owner DB role + RLS | The API connects as the table owner, so RLS is a no-op behind it |
| Real SSRF protection | `collection.fetch()` blocks non-HTTP schemes and private literals; **DNS rebinding is not addressed** |
| Login timing equalisation | A missing account returns faster than a wrong password |
| Compartment registry | Free-text; a typo creates silent no-access |
| Redis isolation | The limiter shares an instance running `allkeys-lru` |
| WebAuthn | TOTP only, and TOTP cannot work on the current dev host |

---

## How to keep this file honest

Add an entry when you build something whose correctness rests on a
judgement rather than on a test. Remove one when the judgement is
confirmed by somebody who can carry it — and record *who*, in
`docs/00-decisions.md`.

The failure mode this file prevents is the one docs/16 names: a system
whose assumptions live only in the heads of the people who wrote it ships,
changes hands, and then somebody discovers an assumption by breaking it.
