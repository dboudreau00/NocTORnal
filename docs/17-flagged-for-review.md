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
| **Durable values for Discord, ICQ, Signal, Wire, Wickr** written before `8595602` | `comms.channel_binding.durable_value` | Discord and ICQ handles without digits normalised to the empty string, which **collides with every other such handle**. Signal and Wire promoted phone numbers and handles their own platform seed says are not durable. | ✅ **Repaired by migration 0038**, recomputed from `observed_value`. Its rules are written literally in the migration (Python, not SQL, because two of them are Unicode-sensitive) and were diffed against the live normaliser over 25 probes. Verify 0038 ran. |
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

### F14 — Which roles may invoke break-glass is a guess

**Built:** migration 0032 seeded `break_glass.invoke` and granted it to
**no role at all**, so the entire feature was unreachable — the permission
existed, the service enforced every control around it, and nothing could
call it. Found by the first e2e test that tried, 2026-07-25.

Migration 0039 grants it to `SYS_ADMIN` and `CASE_OWNER`. That is the
narrowest defensible default, **not a recommendation**: SYS_ADMIN because
operational emergencies are theirs, CASE_OWNER because the commonest real
case is the owner locked out of their own case at 3am. `ANALYST` was
deliberately excluded — docs/05 wants break-glass *available*, and
"available to everyone" is a different property.

**Decide:** who actually needs emergency access in your unit. Getting this
wrong in the tight direction means people route around the system during
an incident, which is worse than the access; too broad and the review
queue becomes noise nobody reads.

### F15 — Phase 4 and 9 SERVICE defects — **FIXED at the service,
2026-07-25**

An adversarial review of `collection.py` and `ingest.py` (their first
ever) found ten defects in the service layer. The routers were patched the
same evening, which closed the reachable attack; the services stayed wrong
for any direct caller — a worker, a script, a future endpoint.

**All ten are now fixed at the service layer, with regressions.**
Migrations 0040, 0041 and 0042; tests in
`apps/api/tests/test_ingest_hardening_pg.py`,
`test_collection_hardening.py` and `test_collection_schedule_pg.py`.

The table below is kept in full rather than deleted. What a defect WAS is
the only thing that makes the fix reviewable, and half of these are the
kind that come back when somebody simplifies the code that prevents them.

| | Service defect (as found) | What now holds it |
|---|---|---|
| **a** | `reveal_credential(credential_id, case_id=…)` checks a live authorisation for *the case the caller named*, then decrypts by credential id with **no join back to the record**. An authorisation on any case decrypted any credential in the corpus, and the audit event recorded the wrong case against the disclosure. | `IngestService` takes `clearance` / `compartments` like `CommsService`, and refuses rather than defaulting — a default would make every caller that forgets silently maximally privileged, which is how this arrived. `reveal_credential` resolves the credential's own case in the SAME query that applies the caller's ceiling, before any decryption or authorisation lookup, and raises `CaseMismatch`. The router maps that to 404, not 403. |
| **b** | `search_by_fingerprint` has no case, classification or compartment predicate — it answers for the whole corpus. | The ceiling is a predicate IN the query. The hit count, the timing and the audit event are now all computed over readable records only — filtering afterwards meant the disclosure had already happened. |
| **c** | `credentials_masked(record_id)` takes only a record id and offers no way to scope it. | `credentials_masked(record_id, *, case_id)` — `case_id` is required and checked against the record's own. Even the masked view discloses which victims of which organisation are in a compartmented case. |
| **d** | `_dead_letter` stores `fragment[:8000]` **verbatim**, and `ingest.dead_letter` has no classification, no compartments and no retention. A `CREDENTIAL_DUMP` or `DATABASE_LEAK` key can be issued with no compartment (only `STEALER_LOG` is gated at issue), and `categorise` routes any record with top-level `email`+`password` down that path — so a whole feed can dead-letter victim PII in the clear. | Migration 0040 gives `ingest.dead_letter` a classification, compartments, a `retain_until` and a `redacted` flag, backfilled from the issuing key — a parse failing does not declassify the data. `redact_fragment` keeps keys, types and lengths and **no leaf value at all**: the shape is the whole diagnostic, because a dead letter exists because a schema changed and a schema change is visible in the keys. A NOT VALID CHECK grandfathers existing rows and refuses new unredacted ones. Retention defaults to 90 days rather than 365 — a dead letter's category is unknown *by construction*. **Outstanding:** `scripts/redact_dead_letters.py --apply` rewrites rows recorded before this; it is irreversible so a human runs it, and the listing endpoint withholds `raw_fragment` on any row still flagged unredacted. |
| **e** | A single NUL byte in a fragment raises `DataError` from inside the `except` handler in `parse_batch`. On an autocommit connection the records already inserted are committed, the bad fragment is **not** dead-lettered, every fragment after it is never processed, and the batch is stranded in `PARSING`. Reached by valid gzipped NDJSON, which docs/12 says to accept. | `scrub_nuls` before the INSERT, the dead-letter write has its own fallback that keeps only the digest and the error class, and `parse_batch` settles the batch state in a `finally`. A batch always ends somewhere. |
| **f** | `fetch()` validates the initial URL and `urlopen` then follows redirects internally, so hops 2..N are never re-checked. Proven: a public host returning `302 -> http://127.0.0.1/` fetched the internal page. `_BLOCKED_NETWORKS` also misses `::ffff:127.0.0.1`, `::`, and the 100.64/192.0.0/198.18 ranges. | `fetch` follows redirects itself with `_NoAutoRedirect` and re-validates **every hop**, bounded at 5 with loop detection. `_is_blocked` asks the address what it *is* (`is_loopback` / `is_private` / `is_link_local` / `is_reserved` / `is_multicast` / `is_unspecified`) and unwraps `ipv4_mapped` and `sixtofour` first — enumerating was the original mistake. Cloud-metadata hostnames are refused by name. DNS rebinding remains the known gap and is still the docstring's stated floor. |
| **g** | `simhash` tokenises with `\w+` over the serialised JSON, so key names count as content and field position is lost. `{"note":"leaked by LockBit","victim":"ACME"}` and its inverse hash **identically** (hamming 0) and the second is marked a duplicate; meanwhile a genuine repost with a mirror's envelope fields lands at 6–13, above the threshold of 3. It false-positives on semantics and false-negatives on its stated purpose. | `simhash_payload` tokenises path-qualified VALUES and drops a mirror's envelope keys. Migration 0041 adds `simhash_version`; existing rows keep 1 and are never compared across the boundary. |
| **h** | `categorise` inspects **top-level keys only**, so `{"log": {...}}` classifies a stealer log as `UNKNOWN` — skipping the compartment check and taking the 365-day default instead of 90. A partner wrapping their payload defeats the control. | `categorise` walks every object in the payload, shallowest first, so the outer document still wins when both match — a chat export containing one quoted credential dump is a chat export. `STRUCTURE_NESTED` records that it was the weaker kind of match. |
| **i** | `RateLimiter` state is per-instance and the router builds `CollectionService` per request, so per-source `max_rps` never fires. Jitter is re-rolled on every `due_sources()` call rather than persisted, so the realised interval depends on how often the scheduler polls, and frequent polling collapses the variance toward the floor — a regular cadence, which is the signature jitter exists to avoid. | Migration 0042 puts `next_due_at` and `last_request_at` on `collect.source`. The schedule is rolled ONCE after a run (including a failed one) and read as-is; the rate-limit gap is measured from `clock_timestamp()` against the stored value, so it survives the per-request service instance. |
| **j** | `redact()` is a keyword list (`password\|passwd\|pwd\|secret\|token\|…`), not structural. `pass`, `p=`, `credential`, `bearer`, `passphrase` and any unlabelled echo pass through. **No live leak today** — `PersonaVault.use()` has no caller and `run_once` passes no secret — but this becomes real the moment the XenForo/Telegram adapters land, which is the next Phase 4 step and the case redaction exists for. | Two layers. `PersonaVault.use` registers the live plaintext in a `ContextVar` for the duration of its block and `redact` removes it verbatim, percent-encoded, form-encoded and base64 — the layer that actually holds invariant 7, because it does not depend on the remote server labelling the field in a way we anticipated. Structural rules (unlabelled high-entropy runs, bare `user:pass` lines, `anything=<long opaque value>`) are the backstop for secrets we do not hold. A readability test guards against a redactor that makes errors undebuggable. |

Two more, lower severity and the same shape, **also fixed**:
`detect_format` was computed at accept time and never consulted by the
parser, so a pretty-printed JSON object — the commonest thing a human
pastes into a feed test — was shredded into one dead letter per line, and
CSV was shredded entirely. `iter_fragments` now tries the whole document
first, then NDJSON, then header-keyed CSV, and it refuses to *guess* CSV
without a consistent column count because guessing wrong turns a combo
list into a hundred thousand one-column records, which is worse than a
dead letter because it looks like it worked. And a batch that yields no
fragments at all is now a dead letter rather than `records=0 dead=0
state=PARSED` — a silent drop with a green light on it.

**What is still open from F15.** Only the data repair: the dead-letter
rows recorded *before* 2026-07-25 are still verbatim on disk. They are
labelled, on a clock and withheld from the API, and
`scripts/redact_dead_letters.py --apply` finishes it.

### F16 — `victim_pii.reveal` is granted to no role

Exactly the defect 0039 fixed for `break_glass.invoke` and did not check
for elsewhere. The permission exists, the endpoint is wired, and
`SELECT role_key FROM iam.role_permission WHERE permission_key =
'victim_pii.reveal'` returns nothing — so the route 403s for everyone.

**Left ungranted deliberately.** Who may decrypt a victim credential is a
docs/16 L2 decision, not a default this build should pick.

F15(a) — the reason to wait — is now fixed, so the blocker is purely the
policy one. When you grant it, `SECURITY_OFFICER` is the wrong holder:
that role grants the *authorisation* and `grant_pii_authorisation` refuses
`granted_to == granted_by`, so giving it both would collapse the two
humans back into one. The shape that works is a case role (`ANALYST` or
`CASE_OWNER`) holding `victim_pii.reveal` while `SECURITY_OFFICER` keeps
`victim_pii.authorise` — the reveal is then always two people by
construction, which is the control docs/12 is asking for.

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

## Reviewed 2026-07-25 — what the second pass cost

The four routers added that day, and the Phase 4/9 services, were both
reviewed the same evening. The routers' findings are fixed and have
regressions; the services' are recorded above as **F15** and are not.

The router findings are worth stating plainly because they were all one
mistake made five times: **`require_global` checks the verb, the account
and step-up, and knows nothing about a case.** Every route that let
`case_id` default to `None` therefore ran with no case check at all.

Reproduced live, by a caller holding only a global role and no
relationship to the victim case:

- a purge with no `case_id` destroyed an exhibit in another owner's
  compartmented case, writing the tombstone under `case_id NULL` so the
  victim case had no record it happened;
- `POST /retention/legal-hold` lifted a court-ordered hold on any exhibit
  in the deployment — which, chained with the above, is the complete kill;
- `GET /retention/due` and `/tombstones` returned object ids, deadlines
  and hold reasons across every case, to a GREEN analyst assigned to none;
- `GET /ingest/records/{id}/credentials` listed which victims of which
  organisation were in a compartmented case.

And two that were simply broken: every break-glass response 500'd
(`awaiting_review` is a `@property` and was being called), so access was
granted invisibly and the review queue — the control — could not be read;
and `parse_batch` read `raw_bytes`, which is a byte COUNT, so `bytes(int)`
shredded a run of NULs into the dead-letter queue on every call.

The suite missed the break-glass one because the only queue test asserted
`200` against an **empty** queue, where the list comprehension never runs.
A test that exercises the empty case is not a test of the serialiser.

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
