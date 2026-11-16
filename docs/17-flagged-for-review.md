# 17. Flagged for review: what was built that may need to change

"It passes its tests" and "it is right" are different claims, and the gap
between them is where this system does its damage. Everything below was built
deliberately, works as described, and rests on a judgement somebody other than
the author should confirm, or is a gap that is known and stated.

Three kinds of entry:

- 🔴 **CHANGE LIKELY.** A defect that is known, reported and not fixed, or a
  decision that is probably wrong for a real deployment.
- 🟠 **CONFIRM THE JUDGEMENT.** A defensible call that a different operator
  would reasonably make differently.
- 🔵 **ACCEPTED COST.** A deliberate trade with a known downside, recorded so
  nobody rediscovers it as a surprise.

For the legal dependencies see
[`docs/16-legal-and-external.md`](16-legal-and-external.md). This file is
about engineering judgement and does not repeat docs/16.

The order is: the data already recorded that should not be trusted; what is
open; the known residuals, by area; the decisions the owner took;
and an index of what is closed, ids included, so that a citation of a closed
id still resolves.

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
| **`KEY_MISMATCH` verifications** recorded before F10a | `comms.pgp_verification` where `outcome = 'KEY_MISMATCH'` and the last field of the stored `VALIDSIG` status line equals `claimed_fingerprint` | The parser compared the claim with the key that made the signature, which is a subkey whenever the vendor signs with one, so a genuine signature by the published key's subkey was recorded as a mismatch. It failed safe; the reading was false. | Verify each again. Do not edit the rows: the ledger refuses it. |
| **`CONFIRMED` bindings** upgraded before migration 0089 (F10b) | `SELECT cb.id FROM comms.channel_binding cb JOIN comms.pgp_verification v ON v.channel_binding_id = cb.id AND v.outcome = 'VERIFIED' AND v.attribution IS NULL WHERE cb.verification = 'CONFIRMED'` | Nothing tied the signing key to the binding's holder, so a guarantor's signed vouch could confirm a vendor's binding. | Verify each again, citing the contact block that ties the key to the holder. |
| **Verifications made with a gpg below the floor** (F10a) | `comms.pgp_verification.verifier_version` below 2.4.9 (2.4 series), 2.5.14, or 2.2.51, or any 2.3 | Those builds carry CVE-2025-68973 (the armour parser) or CVE-2022-34903 (status-line forgery); a distribution build may carry the fixes under an older number. | Confirm the build that made each, or verify again with a current one. A deployment whose image has no gnupg, or whose gnupg is not attested with `NOCTORNAL_GPG_PATCHED_AS`, records `NO_VERIFIER`. |
| **Records written under older rules** | Triage claims accepted before Alpha 6 with no `observed_at`; ATTRIBUTE claims readable below the material they came from, or attached across cases; captured documents cited by cases that share no compartment, which migration 0071 could not label | Each was written under a rule that was later tightened, and nothing can recompute what was never recorded: an observation date, or the lock every citing case's readers hold. They are counted by the readiness rows `triage_claims_dated`, `triage_claims_within_labels` and `captured_documents_compartmented` | `python scripts/legacy_records.py` lists them per case. An analyst decides each: raise an entity, retract a claim, or file the capture again under the right case. An analyst gives a claim its date by superseding it (the inspector's Date this claim); nothing writes a date onto a recorded claim (docs/00 decision 170) |
| **Contact blocks parsed under cb-1 with a gpg-spaced PGP line** (F37) | `comms.contact_block` where `parser_version = 'cb-1'` and an entry has `selector_type = 'PGP_FPR'` with a 20-character `durable_value` | The parser cut the value at the first run of two spaces, so a fingerprint copied from gpg kept 20 of 40 hex characters; a CLAIMED proposal may carry the truncated value, the line cannot confirm a key, and the block is not paired with the same text parsed later | Nothing re-reads a stored block: parse the text again in a case of its own and reject the old proposal. Do not edit the rows |
| **Telegram ids recorded from a bare positive number** before 2026-09-11 | `core.selector` and `comms.channel_binding`, `TELEGRAM_ID` | A bare positive id was assumed to be a user (`u:`), so an MTProto channel observed as a bare number shares a row with a same-numbered user. The normaliser refuses a bare positive now, but nothing can recompute a type that was never observed. | `scripts/telegram_bare_ids.py` lists them per case. Confirm each against its source and re-record typed (`c:<id>`) where a channel is wearing a user's row. |
| **Credentials that stayed after 0137** | `core.assertion.rationale` where an accepted proposal copied its context; `collect.document` text; `core.selector` e-mail rows read out of the userinfo of a link that is not http or https; URL rows of the `url:login:password` layout written before that shape was refused | 0137 scrubbed URL selectors, entity labels, proposals, extraction rows and a correction's `prior_value`, and does not touch a claim's recorded rationale (invariant 5), the captured text or the audit detail | The queries under Known residuals list them. Removing one is an owner decision |
| **Forks in the audit and custody chains from before 0149** | The audit and custody rows at or below the boundary 0149 recorded | Alpha 7a's concurrent writers forked both chains. Verification reports them as legacy and they do not break `intact`; a fork above the boundary is a break | Nothing: they are history, and the log is append-only |
| **Refusals recorded with outcome SUCCESS** before Beta 1.1 | `audit.event` rows whose action is AUTHZ_DENIED, AUTH_SESSION_REJECTED, RLS_BINDING_FAILED, SESSION_BINDING_REFUSED or CASE_SHARE_REFUSED, the sign-in router's cookie, recovery-code and password-change refusals, the PII reveal and search refusals, and the AUTHZ_DENIED and AUTH_FAILED rows of the egress and Telegram persona scripts | A refusal was stored with outcome SUCCESS, so a filter on outcome missed it. Since Beta 1.1 each is stored with outcome DENIED, and the log is append-only, so the earlier rows keep SUCCESS | Find refusals by action and not by outcome for anything recorded before the upgrade. Do not edit the rows: the ledger refuses it |
| **SPF, DKIM and DMARC verdicts on uploaded mail** recorded before 0197 | `deception.email_message` where `auth_basis IS NULL` and any of `spf_result`, `dkim_result`, `dmarc_result` is set | The verdict was believed on where its header sat in the message, which a sender can arrange (http_ui-007), so a recorded `dkim=pass` and its `dkim_domain` may be the sender's. The console marks each "recorded before the mail stamp" | Read each as the sender's claim. A DOMAIN selector proposed from one is checked against the exhibit before it is relied on. Do not edit the rows |

---

## Open

Each entry says what is true, and what to confirm or what the smallest fix
would be.

### 🔴 CHANGE LIKELY

**Nothing is open at this level as an item of its own.** The four items of the
2026-09-22 review were decided by the owner (F2, F14, F16 and F24, under
Decisions the owner took below), and F3 is an accepted cost: it was never a
defect, because the register already refuses on it.

Every entry under **Known residuals** is CHANGE LIKELY unless it says
it is an accepted cost or a judgement to confirm. Read that section before
reporting a weakness: a residual named there is known.

### 🟠 CONFIRM THE JUDGEMENT

#### F4: The parser refuses far more than it extracts

`local@domain` is not resolved without a label (a JID and an email are the
same shape), bare 40-hex is not (SHA-1 is identical), bare 64-hex is not (Tox
pubkey, SHA-256 and OMEMO all match). Each refusal is stored as `UNPARSED`
with its reason, never dropped.

**The trade:** lower recall, and an analyst must label ambiguous lines by
hand. A confident wrong attribution is never revisited because nobody knows to
look, while a refusal is one click from correction. If your analysts find the
labelling burden too high this is the knob, but raise it by adding label
aliases, not by lowering the shape rules.

#### F5: A signed payload must name the identifier, matched strictly

Confirmation requires the identifier to appear in gpg's own output of the
signed region, at a token boundary, at least four characters long. A genuine
signature can therefore land on `VALUE_NOT_IN_PAYLOAD` when the actor printed
the identifier in a different form, spaced hex for instance.

**The trade:** false negatives that cost an analyst a second look, chosen over
false confirmations. Loose matching was deliberately not implemented. Confirm
this is the right side to err on for your evidential standard.

#### F6: The service stoplist is global, and holds identifiers of people who are not subjects

A forum's escrow agent belongs to the forum, so a per-case list would mean
every case rediscovers it by getting the attribution wrong first. The
consequence is a cross-case store of identifiers belonging to escrow agents,
guarantors and administrators who are, by construction, not under
investigation, and entries are retired rather than deleted, so they outlive
the case that added them. docs/16 C12.

#### F7: Co-participation defaults exclude more than they include

Incidental participants and unresolved handles both get no ties by default.
Both are switchable, and switching them draws relationship inferences about
people who are not subjects. The egress gate checks classification, not this
flag. docs/16 C13. A handle resolved to an identity above the reader is, to
that reader, an unresolved handle: drawn and left out with them, and counted
with them unless the case says how many are withheld (decision 232).

#### F8: Break-glass refuses to grant when no security officer exists

Deliberate: unreviewed emergency access is just access. In a small team this
may mean one person wearing both hats, which defeats the separation. Decide
whether to enforce it or accept the risk explicitly, rather than discovering
the gap in an audit. docs/16 D7.

#### F21: The live websocket has no double-submit, by construction

`_handshake` authenticates from `__Host-session` off the upgrade. A
cookie-derived credential elsewhere in this codebase is accepted on an unsafe
method only alongside the `x-csrf-token` header `deps.session_token` demands.
That defence is unavailable here, because a browser cannot set a header on a
websocket upgrade. Two things stand in its place: `SameSite=Strict`, which
stops the cookie travelling on a cross-site upgrade, and an explicit `Origin`
check refused before `accept()`, so a flood spends no budget.

**Confirm the judgement:** those two are not belt and braces. SameSite is
scoped to the registrable domain, so a subdomain this deployment does not
control is inside it, and the `Origin` check is what stands there alone.

#### F25: Exposure levels other than NONE are the operator's word

A lookup provider's exposure (NONE, VENDOR, PUBLIC) decides whether a lookup
needs a colleague's sign-off and which labels may leave. The build checks NONE
as far as the first hop: its route must name a private network and a direct
send refuses an answer from outside it. It cannot check VENDOR or PUBLIC at
all: the level is what an administrator wrote, with a basis, and a second
administrator approved.

**Confirm the judgement:** that a written basis and two administrators are
enough for a claim the software cannot test, for each provider you register.
docs/16 D9.

#### F26: Quota is counted locally and drifts when a key is shared

Each provider's quota is counted from this deployment's own attempt rows,
exactly, in calendar windows. A key also used by another tool, or by a person
in a browser, spends the vendor's quota without this build seeing it, and the
vendor's 429 is then the first sign. The provider cools down for what the
vendor asked, and a refused key locks the provider.

**Confirm the judgement:** that a key registered here is used by nothing else,
or that the quota you enter leaves room for whatever else uses it.

#### F29: Eight platforms in the comms catalogue name selector types the ontology does not have

`comms.platform.durable_selector_type` was seeded by 0034 with nine type keys
the ontology does not define, in fourteen rows. TELEGRAM was corrected to
TELEGRAM_ID (migration comms_platform_telegram_type). The other eight are on
screen in the Comms pane and affect display only: normalisation reads
`comms.PLATFORM_SELECTOR_TYPE`, which holds the right keys. Seven map to an
ontology key (TOX_PUBKEY to TOX_PK, JID to JABBER, MXID to MATRIX_MXID,
BRIAR_PUBKEY to BRIAR_LINK, DISCORD_SNOWFLAKE to DISCORD_ID, ICQ_UIN to ICQ,
SKYPE_NAME to SKYPE_ID); WICKR_ID has no ontology type and needs one first.

**Confirm the judgement:** the seven mappings, and whether Wickr gets a
selector type or its platform row loses its durable type. **Smallest fix:** a
foreign key from the column to `core.selector_type(key)` would stop a ninth.

#### F30: Collected documents are swept only when an operator runs the sweep

`scripts/retention_sweep.py` sweeps collected documents, dead letters and the
ingest records attached to no case (F55) past their retention clock,
deployment-wide, by the same purge every other family uses, so a legal hold on
a document, on any version, or on a case citing it still keeps it. It is dry by
default. A real run needs `--apply`, an authority reference declared
in `NOCTORNAL_RETENTION_SWEEP_AUTHORITY` (recorded on every tombstone and in a
`RETENTION_SWEEP` audit event of counts, refused when missing or a
placeholder, never verified, as the L1 policy reference is) and a named active
account that holds `retention.purge`. It is not in the production cron loop,
and a test holds that; `infra/production/README.md`, Retention sweep, says how
to schedule it. The readiness row `retention_sweep_current` turns red when a
document, a dead letter or an unattached ingest record that no hold keeps has
been past its clock for more than seven days (docs/00 decisions 171 to 173 and
204).

**Confirm the judgement:** that a declared reference and a named account stand
in for step-up on a script that destroys third-party data; that nobody
schedules it until the owner and counsel have said who runs it under which
authority (docs/16 L4); and that the sweep keeps to collected documents, dead
letters and the ingest records attached to no case, and leaves exhibits,
lookups and every record attached to a case to the case's own purge.

#### F32: Key lookups (F10c) take two people and lapse after 24 hours

A Web Key Directory lookup is asked for by a Lead investigator or a Collector
and approved and sent by a Lead investigator or a Reviewer who is not the
person who asked. A request lapses after 24 hours (the schema allows up to
72). Only the hash leaves (no `?l=` parameter, so a directory that looks keys
up by that parameter answers 404), no redirect is followed and no User-Agent
is sent. A key found this way is not confirmed until a person compares its
fingerprint with a published one. **Confirm** the roles, the lapse and the
parameter choice for your deployment.

#### F38: A logout needs no authority, so the client key opens a few small persona tunnels

A stop (a logout) is always allowed, for a persona whose authority was revoked
or which is burnt as much as any other, because refusing it would leave a
session open on the platform. So whoever holds the client key can open four
stop tunnels an hour per persona, each at most 256 KiB and 60 seconds, to that
persona's own sites or its profile's networks, with no authority behind them.
The ledger shows each with a Stop chip.

**Confirm the judgement:** that this budget is small enough to leave
unsupervised, against a logout that sometimes cannot happen at all.

#### F40: The screening match list counts across compartments

The Security Officer's match list is label-free on purpose (docs/00 decision
126): an officer must see every match. The full record opens only within the
officer's ceiling, but the section's status counts include matches in
compartments the officer is not read into, and readiness says only whether
matched bytes are waiting, never how many.

**Confirm the judgement:** that the officer may know how many matches exist in
compartments they cannot open.

#### F41: The object stores are reached outside the egress routes

The evidence, raw, collected-markup and sample buckets are reached by their
own clients on the internal network, not through `route_for`, because they are
part of the deployment rather than outside it. An object store on another host
(an off-host `MINIO_ENDPOINT`) therefore has no route: in the production
topology the application network cannot reach it at all.

**Confirm the judgement:** that the object store stays on the deployment's own
network, or decide how an off-host store is reached and recorded.

Since 2026-11-15 (decision 235, docs/22) an off-host store can be named and is
recorded: the readiness row `object_store_custody_declared` reports it until its
custody is declared, AMBER_STRICT and RED uploads are refused on it until
counsel's declaration is recorded, and each new exhibit's lodging row names the
store's profile and host. It still has no route from the production network;
that is the later step.

#### A claim a dated copy replaced stops scoring in the ACH matrix

Dating an undated claim (`supersede_assertion`) records a copy and marks the
old claim replaced. A stance an analyst put on the old claim is kept and shown
as stale in the matrix and in the report: it counts in no score, ranks nothing,
fills no gap and is never the next test, one warning says how many rows are in
that state, and a new stance on the old claim is refused with a 409 that says to
score the claim that replaced it. A retracted claim still leaves the matrix
altogether (decision 24). The live matrix and the report read it through the one
`ach_cells`, so they agree.

**The trade:** dating a claim that carries stances takes those stances out of
every score until somebody scores the replacement, and nothing does that for
them. Two other rules were weighed. Scoring the old claim as before would let a
withdrawn replacement leave its conclusion standing, which is decision 24 undone
for a replaced claim. Moving the stances onto the replacement at the moment of
dating would write judgements nobody made: a stance is about a claim as it was
recorded, and the copy carries a new date and a new rationale. The conservative
rule costs an analyst a second pass and never overstates what the matrix
supports.

**Confirm the judgement:** that a replaced claim's stance should wait to be
re-scored, rather than score as before or move to its replacement.
(`test_a_stance_on_a_replaced_claim_is_kept_and_shown_stale_and_scores_nothing`,
`test_a_new_stance_cannot_be_put_on_a_replaced_claim_but_a_stale_one_can_be_cleared`,
`test_the_report_scores_without_a_replaced_claim_and_says_so`.)

#### A replaced claim no longer pins its collected document

The retention sweep keeps a collected document that a claim cites. Before 2026-11-15 a claim a dated copy replaced went on pinning its document after the copy was withdrawn, and nothing could release it, because the claim could not be retracted once the retraction of a replaced claim was refused. A document is now pinned by a live claim only (neither retracted nor replaced), so a document whose only citing claim was dated and whose copy was then withdrawn becomes eligible for the sweep, as one whose claim was retracted outright always was. The sweep is operator-run and a dry run by default, and a hold on the document or on a case that cites it still keeps it.

**Confirm the judgement:** that destruction may follow the withdrawal of a replacement, or decide that a replaced claim keeps its pin and may be retracted to release it.
(`test_a_replaced_claim_does_not_pin_its_document_once_its_replacement_is_withdrawn`.)

#### A conversation names a persona only on the persona's own platform

A conversation's collection account is checked since 2026-11-15, and a persona can be named only on the platform its kind belongs to: a Telegram persona on a Telegram conversation, a Discord persona on a Discord one, and a forum persona (XenForo, MyBB, phpBB) on a forum's private messages. No persona kind exists for Tox, XMPP, Matrix and the other comms platforms, so a persona cannot be named as a party to a conversation there. Before, the only way to record one was to name an unrelated persona, which put a false claim in the legal record (docs/16 L4).

**Confirm the judgement:** that a conversation on those platforms is recorded with no persona, or decide which persona kinds belong to them. (`test_an_account_on_another_platform_is_refused_and_stores_nothing`.)

#### A purged exhibit keeps its title

A purge empties an exhibit's description, source address, extracted text and full-text vector, in the update that marks it destroyed (2026-11-15), and keeps its title with the hashes, the size, the media type, the storage key and the acquisition method. The register and the custody trail name the tombstone's exhibit by the title ("the exhibit called X was destroyed on this date"), and a destruction nobody can name is the record this register exists against. A search for a word of the title still finds the destroyed exhibit and its id. An exhibit destroyed before that was emptied of the other four once, by Alembic 0200, and keeps its title in the same way.

**The trade:** a title is often a file name and can be more than that: a line an analyst wrote, or the subject of a message. Keeping it keeps that. Emptying it too leaves the register with an id, a date and a hash, and a custody trail that names nothing.

What the exhibit gave rise to is not part of it and is not emptied: an e-mail's headers, subject and body in `deception.email_message`, a contact block's text, and a capture's records stay, because they are analysis the case rests on (invariant 1) and a purge reaches the exhibit, not the claims made from it. The custody rows, which are append-only, keep what was written into them when the exhibit was lodged, the source address among it; the custody route withholds that address once the exhibit is purged, and shows the rest, the authority reference included (`test_the_custody_trail_of_a_purged_exhibit_withholds_its_source_address`).

**Confirm the judgement:** that the title stays, or decide the register shows a fixed label in its place and the original goes; and whether the records made from a purged exhibit are emptied with it. (`test_a_scheduled_purge_empties_what_the_exhibit_said_and_keeps_its_name`.)

### 🔵 ACCEPTED COST

#### F3: Six retention rules ship with placeholder periods, and collection waits for them

Not a defect. Migration 0032 seeds per-category retention (`STEALER_LOG` at 90
days) with periods somebody typed, and they are a deployment setting: the
right numbers are jurisdictional and no build can choose them. What the build
does is refuse to pretend otherwise. Purge warns on every rule nobody has
confirmed, and `retention_rules_confirmed` is one of the four **blocking**
readiness checks, so a collection poll is refused until a named human has
confirmed each period with a rationale.

**The cost:** a fresh deployment collects nothing until somebody confirms six
numbers. That is the intended cost of a placeholder that cannot quietly become
policy. docs/16 D3.

#### F9: No cryptography is implemented, and gpg is a hard dependency

Verification shells out to the `gpg` binary and parses only its `--status-fd`
output. If gpg is absent the outcome is `NO_VERIFIER` and nothing is
confirmed: there is no path where a missing verifier produces a confirmation.
The cost is an external binary in the trust chain and a version-dependent
status format. The version is recorded on every verification row, so rows made
with a defective build can be found later. A build below the floor counts as
no verifier, gpg never starts an agent (`--no-autostart`), and every key and
detached signature is walked for OpenPGP framing before gpg sees it, which
refuses secret key material outright.

#### F10: Machines propose and never write the graph

The contact-block parser holds no `GraphWriteService`. Every finding becomes a
`collect.proposal` needing a human `reviewed_by`. The cost is that nothing
extracts automatically and the triage queue is the bottleneck. This is
invariant 3 and is not negotiable without changing the model.

#### F11: Co-participation is a projection, never stored edges

Recomputed on every request, so it costs CPU rather than storage and can never
drift from its inputs. Writing it as edges would make a derived tie
indistinguishable from an observed one after the first person forgets, which
is what invariant 4 exists to prevent.

#### F12: Rooms above `max_room_size` are excluded, and each is named

Newman weighting fixes a large room's influence; it does not fix the
combinatorial cost, and a 5,000-member channel still yields 12.5M near-zero
pairs. The cap is real data loss, so every excluded room is reported with its
true size, its roster, which every reader of the room can list (decision 232),
and, where the case says how many are withheld (COUNT), how many participants
were projectable. A cap that drops data silently is worse than no cap, because
the output looks complete.

The Analysis pane's forum and wallet projection (`affiliation.py`) follows
both rules, with one caveat worth flagging: a case records only its own
posters and controllers, so a venue's size in the case graph is a lower bound
(raised by an analyst-recorded member count where one exists), and every
Newman weight drawn from it is an upper bound. Every payload says so. Sizes
are taken from every membership the caller can see before any filter, so the
accepted-ties scope or a confidence floor never shrinks a venue under its cap.

#### F13: CI has no typecheck

Decision 42. There are no annotations to check against, and adding them is a
large, low-yield change to a codebase whose invariants are enforced by
database constraints rather than by types.

#### F22: What the Lab download ticket costs

The download is cross-origin by design, so no `__Host-` cookie can reach it
and nothing HttpOnly can cross. It crosses on a one-shot ticket minted on the
application origin under the cookie session (migration 0061), and that ticket
is legible to any script on the page. The difference from the session token is
what a lift is worth: one sample, one redemption, sixty seconds, against the
case file for twelve hours.

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

#### F27: A vendor answer a lookup adapter cannot read

The VirusTotal v3, Shodan host and MISP restSearch adapters read each vendor's
documented answer shape. A vendor answer the adapter cannot read becomes an
UNREADABLE answer with the raw bytes kept, never a guess. **The cost:** a
vendor that renames or moves a field leaves its answers UNREADABLE until the
adapter is updated.

**A second cost, of the personal-data refusal:** a JABBER address is shaped
like an email address and cannot be told apart from one, so JABBER selectors
are refused with personal data toward every provider.

#### F31: The Telegram end-to-end check, and the supply chain behind it

`scripts/telegram_live_check.py` is the end-to-end check an operator runs with
the deployment's own Telegram account, through the real egress proxy. It
prints one PASS, FAIL or SKIP line per step and no secret. In order, it checks:

1. the egress proxy is configured and in force, Telethon is installed, the
   Telegram ceiling is declared and the deployment is ready;
2. the person running it signs in as the console verifies them and holds
   `collection_account.manage`;
3. `--persona` names a Telegram persona that has an exit;
4. a live collection authority, recorded by one person and confirmed by
   another, covers the persona (and, with `--source`, the source);
5. the persona's run, act and stop contexts resolve on the egress proxy,
   without connecting;
6. the persona is enrolled, or already is;
7. one read-only poll of the persona's Telegram source runs through the
   adapter, the persona's route and the proxy;
8. the persona's own membership of a member chat is read, and nothing is
   joined;
9. the session is logged out at Telegram through a stop route and destroyed
   here.

`--self-check` runs steps 1 and 3 to 5 against the database and the
environment, reports steps 2 and 6 to 9 as SKIP and connects to nothing. A test
(`test_persona_contexts_through_proxy_pg.py`) runs a persona's run, act and
stop contexts through the real listener.

**The supply chain.** Telethon 1.x is maintained by one author, and pyaes,
which it uses for AES-IGE, has had no release since 2017: a flaw in either
lands on the host that holds every persona's session. The DC network list is
Telegram's published one of 2026-09-24, and a new range fails closed until it
is updated.

#### F44: A retention rule confirmed later does not reach documents collected before it

A collected document's clock is set when it is stored, from the category rule
in force then. No FORUM_POST or FORUM_MEMBER rule is seeded, so forum documents
collected before an operator confirms one stay unclocked, and a rule confirmed
later reaches only what is collected after it. Readiness says so while no forum
rule exists. Setting clocks on documents already held is a destruction
decision, and is not made by a migration.

#### F45: There is no source-wide legal hold

A hold is placed on a document, with every earlier version, or on a case, which
holds every document it cites. Nothing holds everything a source has collected
in one act. A case is held from the Hold button in its header or through the
API (`POST /api/v1/retention/cases/{id}/legal-hold`).

#### F46: A raw markup object can be left unreferenced

Raw markup is written to its bucket before the document row that names it.
When storing the row fails and the compensating delete of the object fails
too, the object stays in the bucket with nothing naming it, outside every
retention clock and hold.

**The cost:** rare, and found only by listing the bucket against
`collect.document`.

#### F48: One post read by a board source and a thread source is stored twice

Deduplication is per source, so the same post collected through a board and
through a thread of that board is two documents. The per-forum lock keeps the
request rate right; the analyst sees the post twice.

#### F49: What the forum parsers do not read

An empty MyBB board is recognised only by its English "no threads in this
forum" text, so an empty board in another language reads as parser drift.
XenForo reactions give only the names the reaction bar shows, and its "and N
others" count is read in English only. MyBB reactions are not parsed. Many
boards require sign-in for member profiles, and those pages are skipped with a
warning. An ambiguous MyBB time inside a daylight-saving change is taken as its
first occurrence.

#### F50: That a claim is not in a similarity index stays visible

A claim's similarity reason is told only as its reader may know it: the stored
reason when the reader can read everything the claim cites, and otherwise what
their own readable facts give, or that it cannot be compared. Whether a claim
is in an index at all is still visible, because the claim gate includes the
material it cites.

#### F54: A TELEGRAM_CHAT watch with no term fires on every message

A chat watch with no keyword, selector or pattern matches every message of its
chat, as the schema's "capture everything" says, thinned only by its
suppression window (3600 seconds per chat or topic by default; 0 is one hit per
message). A term in a forum signature raises a hit on every post of that
author, because the signature repeats on each.

### Deferred security items

Not defects, not done. Listed so they are not mistaken for oversights.

| Item | Consequence today |
|---|---|
| Session binding by default | Every session records the address and client it was minted from (0058), and `NOCTORNAL_SESSION_STRICT_BINDING=1` refuses a mismatch with an audit row. A production start refuses to run without it, and `infra/production/secrets.env.example` sets it. In development it is off by default, so a stolen token is portable there |
| WebAuthn | TOTP only. A deliberate absence, stated in four documents; SECURITY.md says reporting it is not a finding |

Row-level security stands on 83 tables and defers none (F51). What the request
role can still reach outside it is under Known residuals.

---

## Known residuals

The gaps that remain, by area. Each entry says what is true, what it costs and
what would close it. An entry marked "decision" records a call the owner may
want to make differently. What Beta 1.1 closed is in the Closed index below,
each with its date and the test that holds it; what stays here is what it left.

### Access control and row-level security

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| the operational tables beside the queues | The request role can still insert and update the three similarity vector tables (`collect.document_embedding`, `core.evidence_embedding`, `core.assertion_embedding`), insert into `lab.yara_compiled_rejected`, and write `collect.collection_run`, the poll runs. Through SQL it could replace an item's vector or mark it failed or excluded, so similarity search misses the item or finds the wrong ones, set aside a valid YARA build so it has to be compiled again, or plant or rewrite a poll run's record. It cannot delete a vector row (0178), and none of these holds case content or a credential. The heartbeat and the queues beside them are closed (Closed index). | Write each on a system connection or through a definer, as 0187 to 0190 did for the heartbeat and the queues. |
| two live LIAISON assignments from before | An account that already held two live LIAISON assignments when a liaison was limited to one case cannot have either extended until one is revoked: extending is a grant on that case, and the other live assignment refuses it. | Revoke one of them; the other is then extended as any assignment is. |
| the fact functions | `iam.case_facts`, `iam.element_facts` and `iam.countersign_blocked_by` answer the labels and the administration metadata of any id, without content. That is by design (decision 141). | Not proposed. |
| session clock | The request role may move its own session's `last_seen_at` forward by up to five minutes past the database's clock (`CLOCK_SKEW` in 0144, stated there as intended: it keeps an API host with a fast clock from failing every request). | None proposed. |
| development without row security | On an owner connection (development, a single-role deployment) the layout lists hidden entities and an ACH stance on a hidden claim answers 200. Under the production role both hold. | None: the request role is the control. |
| a contact block's duplicate | Text submitted as a contact block that was parsed already in the case at labels the caller does not hold is answered as a duplicate, with no field of that block, so the caller still learns that the text was parsed in this case, and from the missing id that they may not read it. | A block per label set, which changes the unique key on `(case_id, raw_sha256)` (a migration); not proposed. |
| a withheld recording's basis | A call whose recording exhibit is above the reader is shown with `recording_evidence_id` null, but its `recording_lawful_basis` is the call's own field, written at the call's labels, and is still returned, so the reader can tell that a recording is held. | Leave the basis out whenever the recording is; decision, since the basis is part of the call's record. |

### Graph, merges and selectors

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| a replaced ACH row in the console | A stance on a claim a dated copy replaced is drawn as a stale row with plain-text cells, so the console offers no way to read its note or clear it. The API still clears it (`DELETE .../stance/{id}`), and the printed report shows its note. | A stale cell that opens the note and a Clear action, with no Score action. |
| a replaced claim and the retraction stamp | The refusal to retract a claim that a dated copy replaced is the service's (`GraphWriteService.retract_assertion`, and the route's 409 over it). The database accepts the stamp on a replaced row, as it accepts a retraction on any row a role may update once (0135), so a runtime role writing SQL could still mark one. Every read treats a row that is replaced, retracted or both as history, so the only cost is a retraction on the record of a claim that was already history. | A trigger refusing `retracted_at` on a row with `superseded_at` set, which is a migration; not proposed. |
| label correction after a retraction | A label correction asks which selector types other entities hold only with the caller's labels. A retraction that restores a label passes none, so the lookup is not made there; a retraction never refuses, so nothing is told. The narrow cost is that the restored label of an entity that owns no index row for its own label (a duplicate of a value another entity holds) is not indexed under that holder's type. | None proposed. |
| a refused reversal names that a later merge exists | The sentence says that a later merge the reader cannot see holds the reversal. That one bit cannot go without allowing the reversal the rule forbids, which would write old endpoints over ties a live merge owns. | None. |
| a merge with one entity the caller can see (decision 230) | A request that names several elements is refused at the first one that fails, as before, so its cost and its row follow that element's place. A merge, a tie or a reversal whose first entity the caller can see and whose second is hidden runs one more full gate before its refusal than a merge naming an id that names nothing, which is refused at the first phantom. | Decide every element's gate before refusing and write one row for the request; that needs an `audit=` flag on `deps.authorize_object`. |
| a probe can be told from a hidden element in the log (decision 230) | An id that names nothing writes the AUTHZ_DENIED row a hidden element writes, with the same keys, types, object, case and outcome. Its `failed_checks` is always `tlp_clearance_dominates` and `compartments_subset` for a caller below RED, and `compartments_subset` alone for a RED caller: lists the gate gives for a hidden element too, but not the spread real hidden elements give. On a queue record and an exhibit's legal hold, which take their case from the element, the phantom is decided with no case, so its list also names `case_assignment_unexpired` and, unless a global role grants the verb, `role_grants_permission`, as a record or exhibit in a case the caller is not on does. Only a holder of the global `audit.read` reads the log. | None proposed: one canonical `failed_checks` for every label refusal would lose which check a real element failed. |
| a route that takes its case from the element (decision 230) | A queue record (`/ingest/records/{id}`) and an exhibit's legal hold (`/retention/legal-hold`) have no case to gate an id that names nothing at. The phantom is decided on its own labels with no case, which costs and records what a record or exhibit in a case the caller is not on costs, except that the row names no case. A record or exhibit in a case the caller is on but above their labels costs one or two reads more and its row names that case. Every record request asks the operator's check first, one or two reads that depend on the caller alone, and a record attached to no case that the check refuses is then gated as the phantom with no case, so it costs and records what an id that names nothing does; the check reads the labels before step-up, so a stale sign-in is told it is stale only about a record the operator may see. Placing a hold on an exhibit above the officer's labels is allowed, as decision 144 says, so it is not refused at all. | None proposed. |
| every id that names nothing writes a row (decision 230) | A missing id now appends one AUTHZ_DENIED row, hash-chained and taking the chain lock that serialises appenders (0149). Graph writes carry only the blanket `request` meter (600 a minute per credential), so one session could write up to 36,000 denial rows an hour and contend on that lock, and a console link to an element that has gone now leaves a row each time it is followed. No test holds that the console never asks again for an element that has gone. The owner deferred a user-scoped `authz.denied` meter, spent by hidden and missing refusals alike, until the real volume is seen. | Measure the row volume in use, then decide the meter. |
| credentials no pattern finds (decision 181) | A secret in a URL path with no separator (`/hooks/<workspace>/<channel>/<token>`), a `?l=` or `?hash=` value whose name does not say it is a credential, a pair with one separator, a pair with no path (`https://y.example:carol:pw`), and a bare `alice:pw@host`, which is read as an e-mail selector. A final path segment with two separators that is not a login pair (a time, an IPv6 address, a URN) is cut as if it were one, so two such URLs can collide in the selector index. | Not detectable by shape. |
| rows stored before the fixes | The 0137 scrub does not touch a claim's rationale, the captured document's text, `audit.event` detail, or an e-mail selector read out of the userinfo of a link that is not http (`mysql://root:Secret123@db.example/app` was read as `Secret123@db.example`). The `url:login:password` layout without an `@` is not cleaned from rows written before the fix either, and no migration was added for it. The queries below find them; run them as the schema owner, they are read-only, and look at each hit before changing anything. A label is corrected through the product, which records the correction as a claim. A claim's rationale is never rewritten by the product (invariant 5): the owner who decides to remove one does it as the schema owner with the `assertion_marked_once` trigger disabled for that statement, and the cost is a claim whose recorded rationale no longer equals what the analyst accepted. | Owner-run, per row. |

```sql
-- Claim rationales that copied a link carrying a password (any scheme)
SELECT a.id, a.case_id, a.node_id, a.edge_id
  FROM core.assertion a
 WHERE a.retracted_at IS NULL
   AND a.rationale ~* '[a-z][a-z0-9+.-]*://[^/?#[:space:]@]+:[^/?#[:space:]@]*@';

-- Entities accepted from a link that is not http or https and carries userinfo,
-- whose label is shaped like an e-mail address
SELECT n.id AS node_id, n.case_id, n.label
  FROM core.node n
  JOIN collect.proposal p ON p.applied_node_id = n.id
 WHERE p.rationale ~* '\m(?!https?://)[a-z][a-z0-9+.-]*://[^/?#[:space:]@]+:[^/?#[:space:]@]*@'
   AND n.label ~ '^[^@[:space:]]+@[^@[:space:]]+$';

-- The stealer layout url:login:password written before the fix
WITH shape(re) AS (VALUES (
  '^[a-z][a-z0-9+.-]*://[^/?#]+(/[^/?#]*)*/[^/?#:|@]*[:|][^/?#:|@]+[:|][^/?#]+([?#].*)?$'))
SELECT 'core.node' AS "table", n.id, n.case_id, 'label' AS "column"
  FROM core.node n, shape WHERE n.label ~* re
UNION ALL
SELECT 'core.node', n.id, n.case_id, 'attrs.raw_value'
  FROM core.node n, shape WHERE n.attrs ->> 'raw_value' ~* re
UNION ALL
SELECT 'core.selector', s.id, s.case_id, 'raw_value or norm_value'
  FROM core.selector s, shape
 WHERE s.selector_type IN ('URL', 'SOCIAL_URL')
   AND (s.raw_value ~* re OR s.norm_value ~* re)
UNION ALL
SELECT 'collect.proposal', p.id, p.case_id, 'payload label or raw_value'
  FROM collect.proposal p, shape
 WHERE p.payload ->> 'label' ~* re OR p.payload -> 'attrs' ->> 'raw_value' ~* re
UNION ALL
SELECT 'collect.extraction', e.id, NULL, 'raw_value or norm_value'
  FROM collect.extraction e, shape
 WHERE e.selector_type IN ('URL', 'SOCIAL_URL')
   AND (e.raw_value ~* re OR e.norm_value ~* re);
```

The last query's shape also matches the false positives named in the previous
table. The pasted line itself stays in the captured document's text and in any
claim rationale that copied its context.

### Evidence, retention and reports

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| the purge preview moves with the whole case | A dry run's `preview` is made over everything due on the case, so it changes when an item the caller cannot see falls due or comes under a hold, and a real run that presents the old one is refused with the stale-count sentence. A caller who runs two dry runs and sees the list unchanged while the preview moved learns that something unseen changed, not what or how many. Under NONE that is all there is left to learn. | Bind the preview to what the caller may see and leave the rest to the sweep's own recheck under locks, which would let a hold placed on an unseen exhibit between the two pass the gate. Not proposed: the binding to the whole case is the guard. |
| the tombstone and the out-of-schedule purge | `purge_due` marks each exhibit destroyed in the transaction that deleted it and writes the tombstones afterwards. If a tombstone cannot be written the exhibits are destroyed and marked and the error says how many; they are no longer due, so another purge does not write it. `purge_out_of_schedule` is one transaction with the approval's spend, because the approval must be spent with the destruction, so a failure there after a store delete rolls the marks back, leaves the approval usable and the object gone. A destroying Lab rejection opens a second, system connection for the length of the delete, to hold the case row. A tombstone, and the Destroyed list that reads it, total everything a batch destroyed, exhibits above the caller included, because counts per label would need data the tombstone does not store. | None proposed. |
| a compartmented report | A report that carries a compartment is refused by the egress gate for every destination, because compartmented material does not cross the boundary at all: a lead read into a compartment can never release a report on a case that holds compartmented material. | None proposed: it is the gate's rule. |
| a refused case-hold lift | A refused case-hold lift, or a refused request for its second signature (decision 229), names nothing above the lead under NONE, but the refusal itself differs from a request or a lift that succeeds, which no wording can hide. | None. |
| same bytes at other labels (0141) | The same bytes at different labels are separate exhibits, each with its own object, custody trail and register row. A case can therefore hold several copies of one file. The upload route takes a classification and no compartments, so lodging the same bytes into another compartment is reachable only through the service (capture, lookups, deception e-mails). | None proposed. |
| rows from before the key fix | An exhibit stored at a nested key before the key fix (development and test databases only, since no released build wrote them) stays unpurgeable. | Re-lodge it. |
| exhibits lodged before the byte check | The flag that keeps an exhibit's bytes off the application origin, `is_hostile_markup`, is derived once, when the exhibit is lodged, from its declared type, its leading bytes and a markup extension on its title or on the uploaded file's name. An exhibit lodged earlier as `application/octet-stream`, or with no type, and not marked then keeps `false`: `GET .../content` and `POST .../export` still serve its bytes from the application origin, and the console saves an export under its title's extension, `.html` included. So does a new upload of the same bytes at the same labels, which is deduplicated onto the old row. The request role cannot change the column (0178), and the file name an upload carried is not stored. | The schema owner marks the rows the query below finds by title. The bytes cannot be searched by SQL, so an exhibit whose title does not say is marked by its id once somebody has looked at it. |

```sql
-- Exhibits whose title ends in a markup extension and that were lodged unmarked
SELECT id, case_id, title
  FROM core.evidence
 WHERE NOT is_hostile_markup
   AND title ~* '\.(html?|xhtml|xht|shtml|mhtml?|hta|svgz?|xml|xslt?|emlx?|mbox|har)[[:space:].]*$';
```

### Sessions, HTTP and the console

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| rows from before the keyed hash | `audit.event` and `lab.download_ticket` rows written before 2026-11-15 keep what they recorded: a failed sign-in's `email` as typed or its unsalted `email_sha256` prefix, and an `ip_hash` that is a plain 32-byte sha256. They stay as guessable as they were, to anyone who can read them, because the log is append-only and its chain hashes the stored value. They are told apart by `detail ? 'email'`, `detail ? 'email_sha256'` and `octet_length(ip_hash) = 32`; a keyed row has `email_hmac` and a 16-byte `ip_hash`. | None proposed: they are history. |
| a recovery-shaped sign-in costs eleven verifies | A sign-in whose second factor is shaped like a recovery code costs one password verify and ten recovery verifies, whoever sends it and whatever account it names, so how long it takes says nothing about the password. The cost is eleven times an authenticator-coded attempt's. A source's failed attempts are capped by `auth.login_failed` (30 in five minutes, read before the verify), so one source can now draw 330 Argon2id verifies at 64 MiB from the server in those five minutes where it drew 30. The cap is per source, so a spread of sources multiplies it as it already did. | Weight the attempt meters by the verifies a request will run, which needs the route to read the body before the meters do. |
| a refusal after both factors clears the failure count | A sign-in that proves the password and the second factor and is then refused, with a 403 because the password was issued or a 409 because a new password was sent and none is pending, clears the account's failure count and, for an authenticator code, spends its step, though no session opens. Both refusals are audited. Whoever reaches them holds the password and a current code, so nothing is gained against a lockout. The independent review proposed clearing the count only where a session is minted; it was not done, because the 403 has cleared it by design and a test holds that. | Clear the count in the handler, only where a session is minted: the typos before a refused sign-in would then keep counting, and `test_a_refused_sign_in_still_resets_the_failure_count` would change with it. |

### Egress, notifications and collection

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| the Received boundary of an unstamped message | An uploaded message's `Received` chain is still read by where its lines sit: a sender who writes a top `Received: from x ([203.0.113.9]) by mx.<trusted host>` line makes that hop the trusted boundary (`parse_received_chain`), and `selector_candidates_for_email` proposes the address the sender chose as a durable IPV4 selector. The mail stamp (http_ui-007, closed 2026-11-15) settles which `Authentication-Results` header is believed, not this; until it is closed, treat the sending host of a message with no valid stamp as the sender's claim. | Mark the boundary confirmed only at the hop the stamp binds (`rh` in `X-NocTORnal-Stamp`), and every hop of an unstamped message assumed. The signers need no change. |
| echoed secrets in a transformed form | The member walk removes the persona's password and session cookie exactly, in the plain, URL-encoded, form-encoded, base64 and (for markup) HTML-escaped forms, and only for a secret of at least six characters. A board that echoes a transformed form (hashed, case-changed, split across tags) is not caught. | None proposed. |
| the feed parser and a wide feed | A clean BOM-less UTF-16 feed that does not start with an XML declaration is refused too, and says why. No such feed is known. | None. |
| the SENDING update of a key lookup | The approval of a Web Key Directory lookup reads the case, and the contact block and channel binding the lookup cites, again, and refuses when a cited row has been raised above the lookup or has gained a compartment since it was asked. The case row does not move with them, and the cited rows can be raised by the schema owner, `noctornal_worker` or any writer with UPDATE on the two tables; no route does. `comms.guard_pgp_key_lookup` still repeats only the case's half on the update to `SENDING`: its comparison of the cited rows is in the INSERT branch. A writer that skips the service can commit `SENDING` for a lookup whose citation was raised, and the hash of the address's local part then leaves for the directory; a key found is refused afterwards by the acquisition guard, and the lookup stays `SENDING`. The cited rows are read before the send is committed, so one raised between that read and the fetch is not seen, as the case is not. | A migration that gives the `SENDING` branch the INSERT branch's comparison for both cited rows; it needs a revision, and none was assigned (the gap is held by `test_the_sending_update_does_not_yet_compare_what_the_lookup_cites`, which fails when it closes). |

### The Lab and the isolated worker

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| lab-6 | A duplicate upload is refused (409) when the bytes are already held and accepted (201) when they are not. The refusal names no hash and says nothing more to a caller who may not see the existing sample, and nothing is stored in the prober's name, but the status code is still one bit across a compartment or label boundary: a holder of `sample.submit` who has a candidate file can learn whether this deployment already holds that exact file in a case they cannot see, which is the fact that somebody else is working the same intrusion. A probe that is accepted stores a sample, so each probe of a novel file leaves a row. This is inherent in content deduplication (`samples.py`, the comment at the dedupe branch, and `test_review46_duplicate_residual_pg.py` pin what still holds). | Store a second copy per label set, which for live malware is a decision for the owner. |
| a download ticket is burned before the refusal | A download ticket is spent, and a `SAMPLE_DOWNLOAD_TICKET_REDEEMED` audit row written, when it is presented, before the download checks the caller's live clearance and the sample's screening state. If the download then refuses, the holder gets "no such sample", the ticket is gone, and there is a REDEEMED row and no `DOWNLOADED` custody row, so the audit row reads as a redemption that served nothing. Spending first is deliberate (one statement makes the ticket one-shot); `lab.sample_access` is the record of what was served. | None proposed. |
| YARA sources ship unpinned | `yara/sources.json` ships with no pin on any of its nine sources, so `scripts/yara_db.py fetch` refuses every one of them until an operator runs `fetch --update` once, reads the rules it pulled and puts the commits it printed on the entries (`yara/README.md`). | An operator's review: that is what a pin records. |
| the lab-triage loop while no policy is declared | With no prohibited-content policy declared (docs/16 L1), every pass of `scripts/lab_triage.py` prints `refused:` and exits 1, so the production `lab-triage` service logs `lab_triage exit=1` on every pass until the policy is declared. | Declare the policy, which is for counsel (docs/16 L1). |

### The ledgers and the migrations

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| the tail anchor is the operator's | A verification cannot see the newest rows being cut off or the chain being rewritten and re-hashed by the owner. With an anchor held on a file the host cannot write, deleting the tail answers `ANCHOR_MISSING` and rewriting it `ANCHOR_REWRITTEN`; nothing records the anchor on its own. | Schedule `scripts/audit_verify.py --record` from a host that holds the file. |
| owner and worker rows | The owner and `noctornal_worker` keep whatever actor and time they supply, and their rows can sit slightly out of time order. An owner who inserts a row forked off a pre-boundary row would be counted as a legacy fork. `INSERT ... RETURNING seq, prev_hash` on a row the writer may read returns the newest seq and hash of the whole log (0169 documents it, and no application code asks for a row back). | None: they need owner rights. |
| 0134 holds a table | 0134 holds `core.selector` locked about 24 seconds per 300,000 rows; no faster form was found (dropping and rebuilding its trigram indexes around the rewrite measured 22 seconds against 20). | None. |

### Deployment, installers and backups

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| no Kubernetes path | The application can be probed, its worker can be reached over mutual TLS and its egress boundary can rest on a NetworkPolicy (decision 239), but no manifest is shipped and nothing here has run in a cluster: the readiness rows `sample_static_analysis`, `egress_boundary` and `collector_split`, `/readyz` flipping to 503 before the migration Job has run, and the worker starting with the kubelet's variables present are untested against a real one. The egress canary cannot prove that it is running: an unanswered connection is what a policy that holds looks like and also what a canary that is not running looks like, so the operator confirms once, from a pod the policy allows, that it answers. A deployment on Kubernetes is the operator's to write until the manifests exist. | The kustomize base of `kubernetes-manifests` and a verification run on a cluster that enforces NetworkPolicy. |
| the worker's TCP channel | A worker reached over TCP (`NOCTORNAL_ANALYSIS_LISTEN`) carries decrypted sample bytes and takes any certificate its one CA issued, whatever the name on it, so the CA must be the channel's alone: a CA that also issues other certificates lets their holders call the worker. The worker does not read a name off the certificate to tell the api, the collector and lab-triage apart. Its isolation from the network is proved by a self-test that dials the database and the canary (as addresses this process resolves, since a worker with no DNS answers no to every name), not by an empty interface list, so a pod's NetworkPolicy is what keeps it away and the register says so. The other direction is not proved at all: nothing here shows that an ingress policy admits only the api, collector and lab-triage pods, and the worker's own bound on connections still in their handshake limits what a peer with no certificate can hold without stopping it from connecting. It reads its certificate once, so a renewal is a rollout. | A dedicated CA kept by the operator, and a name check per caller if an agency asks for one. |
| the `.env.local` deny list | The loaders (`release/install.sh`, `scripts/launch.sh`, `scripts/_env.py`, `release/install.ps1`, `scripts/launch.ps1`, `scripts/open-ui.ps1` and the one-line loader in `release/INSTALL.md`) leave out names that change how the next program starts: `DOCKER_*`, `COMPOSE_*`, `GIT_*`, `PIP_*`, `NODE_*`, `PSModulePath` and the earlier set. A name outside the list still loads: `HTTPS_PROXY`, `SSL_CERT_FILE` or `REQUESTS_CA_BUNDLE` are read by pip and the other tools the installer starts. An allow-list would silently stop loading every new setting, which is a quieter failure; the attack needs a handed-over `.env.local` on the victim's machine. | Add a name to every loader's list when a tool is found to read it. |
| the bundled store and its tools | The production compose still starts MinIO and makes its buckets and accounts with `mc` (`minio-init`), and the documented backups are `mc mirror`. Another store runs through `compose.external-store.yml` (docs/22), with its buckets made by `scripts/object_store_provision.py` and its accounts by the store's own tools. The conformance suite has no CI leg: it was run by hand on 2026-11-15 against the pinned MinIO and Zenko CloudServer. | Ship a non-MinIO store option, retire the `mc`-based init and backups, and give the suite a CI leg, the later item. |
| a MinIO key is an argument, once | `mc admin user svcacct add --secret-key ...` for the `SAMPLE_` and `PRESERVE_` accounts is visible in the host's process list for the moment it runs, the first time each account is created; its stdout, which echoed the secret into `docker logs minio-init`, is discarded. One bucket each, once, and `hidepid=2` on the Docker host hides it from other local accounts. | `mc` takes the key only as an argument. |
| the ACME override's route out | Under `infra/production/compose.acme.yml` Caddy joins `edge` and can reach the internet, because Let's Encrypt has to be reached; it still shares no network with the database, Redis, MinIO or the egress proxy. The default, `NOCTORNAL_TLS_MODE=internal`, gives it no route out (decision 236). | A certificate issuer of its own that holds the ACME account and hands Caddy a file certificate, which Caddy does not reload without a second moving part. |
| the internal CA's key and its dates | `scripts/internal_tls.py` writes `tls/ca/ca.key` on the host to issue the certificates, and while it stays there root on the host can mint a certificate for `minio`, `postgres` or `redis` that every service trusts; keeping it elsewhere is the operator's (README step 3). Nothing renews a certificate by itself: a server certificate lasts 1095 days, `internal_tls.py check` fails within 30 days of an end, and a certificate past its end stops every client that verifies it. | A CA held offline or in hardware, and a renewal the stack runs itself. |
| the host rule under `ingress` | A connection Caddy starts leaves the host's interface with a private source address nothing routes back, unless the host drops it; the `DOCKER-USER` rule that does is described in `infra/production/README.md` and installed by nothing (the owner's decision). | The operator adds the rule to the host's firewall. |

### Load and performance

Measured on a database of 300 users and 60 cases with one AMBER case of 101,000
entities, 300,000 ties and 1,000,000 claims, at 1, 10 and 50 concurrent users
(`release/CHANGELOG.md`, Beta 1 and Beta 1.1, has the numbers).

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| the ceiling | Writes, entity and claim reads, selectors, search and audit hold at 100,000 entities and 1,000,000 claims per case, with single-user reads under a second but for the report build, which takes seconds, and no errors at 10 concurrent users. The canvas, the metrics and the report are built for about 5,000 entities per case and past that answer truncated; the ego network stops at 5,000 entities and says so, and a path search that reaches 5,000 answers 422. At 50 users cheap reads reach about 3 seconds at the 95th percentile. | Not proposed. |
| measured on one host | Every number is from a Windows host talking to Postgres in WSL2, where a statement costs about 1.2 ms of round trip. The fixed per-request cost and the throughput ceiling are pessimistic for a Linux deployment. | None proposed. |

### Tests and code structure

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| the shared `client` fixture | 82 of 99 `client` fixtures repeat the same app and limiter set-up. | One `api_client` fixture. |

---

## Decisions the owner took

The owner's instruction on the roles was "keep the split": `CASE_OWNER` is the
law-enforcement or threat investigator who controls their case, displayed as
**Lead investigator** (the key is unchanged, so no permission check moved), and
`SECURITY_OFFICER` is the independent overseer who cannot read case content.
F14 and F16 follow from that, and migration 0062 holds both. The first four
decisions below were taken on 2026-09-22, the four after them on 2026-10-08,
and the last on 2026-11-14.

### F2: a `REJECTED` sample is preserved, and destroyed only by declaration

**Why:** destroying the bytes and the data key was the default, and in a
jurisdiction that requires preservation of prohibited material for a designated
authority, destruction is itself an offence.

**Decided:** preserve by default. A rejected sample's encrypted bytes move into
their own store (`PRESERVE_BUCKET`, default `noctornal-preserved`, a bucket
created with object lock) under a legal hold on that object version, and the
data key is kept. Retrieving one is a two-person act, the same shape as the
victim-PII reveal: `sample.preserved.authorise` is the Security Officer's alone
and `sample.preserved.retrieve` the Lead investigator's, and the pair is in
`iam.separated_duty` so no role can be given both. Destruction happens only
where the deployment declares `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=destroy`,
and never under a legal hold, which refuses it. docs/11 has the mechanism.

The register states it: `prohibited_content_policy` (docs/16 L1) names the
disposition in its evidence, preserved into which bucket or destroyed, and
`preservation_bucket_object_lock` proves that bucket is write-once the way F24
describes, and fails by name on a disposition that is neither value. What stays
with counsel: whether this jurisdiction wants preservation at all, and for whom
(docs/16 L1).

### F14: break-glass holders

The grant of migration 0039 stands. `break_glass.invoke` stays with `CASE_OWNER` and `SYS_ADMIN` (operational
emergencies are the administrator's, and the commonest real case is the Lead
investigator locked out of their own case at 3am); `break_glass.review` stays
with `SECURITY_OFFICER` only. `ANALYST` stays excluded, because "available to
everyone" is a different property from "available". Migration 0062 puts invoke
and review in `iam.separated_duty`, so a later grant cannot let a role review
its own emergencies.

### F16: victim PII is two people by construction

`CASE_OWNER` holds `victim_pii.reveal` and does not hold
`victim_pii.authorise`, so authorising is the Security Officer's alone
(migration 0062). The reveal is two different people by construction: the case
gate reads the permission off the caller's one role on the case, so a Lead
investigator on their own case can reveal and cannot authorise, and an officer
assigned to the case as `SECURITY_OFFICER` can authorise and cannot reveal (and
reads no case content). Even the first-run operator, who holds both roles
globally, cannot authorise their own reveal. `iam.separated_duty` refuses any
grant that would give one role both halves, and the upgrade refuses to install
the guard over a role that already has them. The lawful basis for holding the
data at all is still docs/16 L2, which no grant settles.

**The transition.** Before 0062 a Lead investigator could authorise a co-lead
on the same case for up to 30 days; that row opened nothing while nobody held
`reveal`, and afterwards the co-lead holds it and the lookup never asks who
granted the row. So 0062 revoked every live authorisation whose grantor holds
no role on the case that may authorise today, and wrote an audit event for each
(`PII_AUTHORISATION_REVOKED`, actor kind SYSTEM, naming both people and the
migration). Authorisations a Security Officer granted stand. A downgrade does
not restore the revoked ones.

### F24: the evidence store's upstream is archived

The open-source MinIO server, client and KES are archived, unmaintained and
outside security support, with vulnerability reports not accepted
(`https://dl.min.io` answers 410 Gone). quay.io served the last community
builds until 2026-09-25; the CI step and both compose files pin the same
builds, mirrored byte for byte to this project's GHCR namespace, for
linux/amd64 only: an ARM host cannot pull them.

**Decided: stay on the pinned build, with the risk accepted in writing** (by
the owner, recorded here). The exposure is bounded by the store being an
internal, non-internet-facing service in the production compose. The
acceptance comes with one change: the readiness register does not **read** the
bucket's lock configuration, it **proves** write-once.

Why a configuration read is not evidence:

- **SeaweedFS** accepts a COMPLIANCE retention and has let the delete succeed
  anyway. Issue 8350 (SeaweedFS 4.12, closed as not planned) reported a delete
  before the retain-until date succeeding by writing a delete marker; issue
  11333 reported a DELETE naming the locked version's id succeeding before
  `RetainUntilDate`. A store in that state answers a lock-configuration read
  exactly as MinIO does.
- **Garage** implements no S3 object lock at all (its S3 compatibility
  reference; feature request 1127 on its own forge).
- **Ceph RGW** is maintained and implements S3 Object Lock in GOVERNANCE and
  COMPLIANCE modes. It is the self-hosted option if the pinned build has to be
  left, and a storage-adapter change rather than a model change, because
  `EvidenceStorage` already speaks S3.
- **A vendor-operated S3** (AWS S3 Object Lock and its peers) changes where the
  evidence physically sits and who can reach it, so it is a custody question
  for docs/16 C2 before it is a technical one.

**What the probe does** (`readiness.prove_write_once`). One canary object per
bucket at a fixed key (`.noctornal-worm-canary`), written with a one-day
COMPLIANCE retention only when it is absent or about to lapse; every probe then
issues a DELETE of **that version id** and passes only when the store refuses
it for retention and the version is still there. The version id is the test: on
a versioned bucket a DELETE without one adds a delete marker and succeeds,
which proves nothing (8350 above reads exactly like that). It runs against the
evidence bucket (`evidence_bucket_object_lock`) and the preservation bucket
(`preservation_bucket_object_lock`), with the register's usual short timeouts
and a ten-second budget for each check's whole proof. Canary versions whose day
has passed are removed by the next probe that succeeds, so each bucket carries
one or two, not one per day for ever. That tidy is best effort: any failure in
it, a dropped connection included, is noted beside a proof that stands and
never turns the row red.

**The mode is read, not assumed.** A plain DELETE is refused under GOVERNANCE
exactly as under COMPLIANCE, and GOVERNANCE yields to anyone holding the bypass
permission, the root credential included. So after writing a canary the probe
reads back the retention the store recorded, and a canary carrying any mode but
COMPLIANCE fails the check by name; it is not replaced, because on a store that
downgrades every replacement would be one more version locked for the bucket's
default period. Credentials that may not read a retention still get a verdict
from the refused DELETE, and the evidence then says COMPLIANCE was requested and
not confirmed.

**Each bucket is proven for the lock it relies on.** An exhibit carries a
COMPLIANCE retention, so the evidence bucket gets the proof above. A preserved
sample carries a **legal hold and no retention** (F2), and a hold is a separate
S3 mechanism: its own header, its own API, and an enforcement path a store can
get wrong while getting retention right. So the preservation check also proves
the hold (`readiness._prove_hold`): a second canary at `.noctornal-hold-canary`,
written the way a rejected sample is written (hold in the PUT, then read back
as ON) by the account rejections are preserved with, then a DELETE of that
version id that must be refused with the version still there afterwards. Both
proofs must pass. A hold has no expiry, so that one held version is kept for
good and never tidied; if its hold is ever lifted by hand, the next probe
writes a fresh held one. On the pinned MinIO a held version is refused with the
same answer as a locked one ("Object is WORM protected"). Whatever store this
deployment moves to, both checks must pass on it before an exhibit or a
rejected sample is written there.

**A refusal is the hold's only when no retention could have made it.** An
unexpired retention of any mode refuses a plain DELETE with the same code and
words as a hold, and a bucket's default retention rides on a PUT that asked for
none, so a store can enforce that and not the hold at all. Before the DELETE the
probe reads the held canary's retention back, with the first credential here
that may read one (the preservation account in the production compose may not,
so it is the one that makes the DELETE), and the check passes only on an answer
of none: a held canary that carries a retention is passed over for a fresh one,
a fresh one that carries one fails the check and names the bucket default, and
no credential able to read it fails it too. The evidence says who read it.

**A refusal only counts from credentials allowed to delete.** On the `minio`
profile an `AccessDenied` is the account's policy, not the lock, so it never
passes. On the `s3` profile (decision 235) an `AccessDenied` is what AWS,
CloudServer and Ceph answer for a locked version too, so it counts only when a
delete-marker permission control has shown the credential may delete versions in
that bucket and the version's retention or hold reads back as in force. The preservation
account in the production compose is minted unable to delete or set a
retention, on purpose, so its attempt always ends there; the check then makes
the proof with the `MINIO_*` credentials when they address the same store, and
says so in the evidence. It fails, and says the proof cannot be made from this
process, when no credential here may delete on that store, and it fails without
trying anything else when the account rejections are written with cannot even
read the bucket, because then every rejection is refused. The hold proof keeps
the same line: the held PUT and the read-back are always the preservation
account's, because they are the steps every rejection takes, and only its
DELETE moves to the `MINIO_*` credentials. Both paths were run against the
development MinIO with throwaway accounts carrying the production policies.

**Reopen** if a vulnerability is published against the pinned build that is
reachable from inside the deployment's network, or if the store is ever exposed
beyond it. The exit is now configuration, not code (decision 235, docs/22): a
store that passes the conformance suite and both register rows on its profile is
an acceptable one. On 2026-11-15 the suite and the rows passed on the pinned
MinIO (`minio` profile) and on Zenko CloudServer 8.8.32's in-memory backend (`s3`
profile, which refuses a locked version with `AccessDenied`); Ceph RGW has not
been run.

### Compartmented sources keep being polled, and collection's ceiling stays label-only

Taken on 2026-10-08 (docs/00 decision 202).

**Why:** collection's ceiling checks (`collection.py` `_feed_floor_refusal`,
`collection_authority.ceiling_refusal` and `telegram_service.py`) hand the egress
gate a source's TLP level and no compartments, and the gate refuses compartmented
material outright, while F43 lets a source carry compartments and polls it on
purpose. The register asked which of the two is right.

**Decided:** a compartmented source keeps being polled. What it collects carries
its compartments (F43), so the readers, the notices, the Telegram path and the
capture path hold it to them; the ceiling decides only whether the fact of
reading the source may leave the platform, which is a question about its label.
Nothing passes the compartments to the gate.

### A sample download is not an egress

Taken on 2026-10-08 (docs/00 decision 203).

**Why:** `SampleService.download` never calls `can_egress`, while the production
of an exhibit containing attacker markup does, and the register asked whether a
download is egress.

**Decided:** it is not. The one-shot ticket stands as its design (F22): a
download is an analyst's authorised act on a sample they may read, behind a fresh
second factor and a ticket spent once, whose redemption re-derives the holder's
live permission, clearance and compartments and the sample's screening state
before a byte moves, and it hands over the encrypted archive from the separate
sample origin. No `can_egress` call is added.

### F55: dead letters and ingest records attached to no case join the sweep

Taken on 2026-10-08 (docs/00 decision 204).

**Why:** a dead letter carries a 90-day clock and third-party victim data, and was
reached only by `purge_due(case_id=None)`; the case-scoped purge route skips it by
design and the F30 sweep kept to collected documents, so nothing destroyed one when
its clock ran out. Ingest records attached to no case were in the same position.

**Decided:** both join the operator-run sweep, which is built. `scripts/retention_sweep.py`
destroys them under the same declared authority and named account as before, dry by
default, and nothing schedules it. A dead letter's tombstone carries no case, so the
cross-case concern decision 172 names does not apply to it. An ingest record attached
to a case stays that case's, with its clock and its hold. The readiness row
`retention_sweep_current` counts all three families.

### Retiring an entity over a tie the caller cannot see

Taken on 2026-10-08 (docs/00 decision 205).

**Why:** the refusal said, under every setting, that a tie above the caller touches
the entity, while docs/14 U2 makes what is said about withheld material a per-case
setting.

**Decided:** the retirement stays refused whole, and under a case whose
`withheld_disclosure` is NONE the refusal reads like any other refusal of an act that
was not done: "this entity was not retired and nothing was changed. If it should be
retired, ask the case's lead investigator." It names no tie, no clearance and no
compartment. PRESENCE and COUNT keep the sentence that says why. The live-merge guard
answers in the same words as the tie guard under each setting, so the two cannot be
told apart, and a setting that cannot be read counts as NONE.

### Lifting a hold takes two people

Taken on 2026-11-14 (docs/00 decision 229, superseding decision 193).

**Why:** lifting a hold is what makes a later destruction lawful, and it was one
person with a written reason. A review had suggested two people and the owner kept one
(decision 193).

**Decided:** lifting takes two people, for an exhibit's hold, a case's and a collected
document's. The one who lifts asks for a second signature from the hold itself; a
colleague who could lift it too, cleared for everything it releases, approves with a
sign-in from the last 15 minutes; the one who asked spends the approval once, within
72 hours (a court order signed late on a Friday is still answerable on the Monday),
on the hold as it stood when they asked. The database refuses a lift without it. The
second person is not seasoned, and whoever placed the hold may be either half.

---

## Closed

Kept as an index, because the value of this register is that a reader can tell
a judgement nobody has confirmed from one that somebody has, and so that a code
comment that cites a closed id still finds it. The reasoning behind each
closure is in `release/CHANGELOG.md` under its date. The rows dated 2026-10-08 are
what Beta 1.1 closed, in the order of the areas under Known residuals.

| Id | What it was | Closed |
|---|---|---|
| **a recovery code's timing (SIGNIN-01)** | A correct password with a second factor shaped like a recovery code cost one Argon2id verify for each recovery hash the account held, on top of the password's, and a wrong password or an address with no account cost one, so a caller who timed the answer learned that the password was right while the status, the body and the audit row were the same (the independent review of Beta 1.6) | 2026-11-15: a recovery-shaped code costs one password verify and exactly ten recovery verifies (`recovery.CODE_COUNT`, the most an account holds) on every path, an unknown address, a wrong password and a closed or unenrolled account included, the dummy hash padding what the account does not hold, and a path that fails before the second factor counts never reads the stored hashes; an authenticator code still costs one verify. Status, body, audit rows and lockout are unchanged (`test_a_recovery_shaped_code_costs_the_same_work_on_every_path` and `test_a_six_digit_code_still_costs_one_verify_and_no_recovery_work` in `test_login_timing.py`, and on the two routes that check a password, `test_a_recovery_shaped_code_costs_the_same_on_login_and_on_the_account_password_route` in `test_login_timing_pg.py`); what the work costs a source is in Known residuals |
| **a sign-in refusal with no row (SIGNIN-02)** | A sign-in that proved a password and a second factor and sent a new password for an account with none pending was answered 409 with no audit row, though the check had already spent an authenticator step and cleared the failure count, and every other outcome of the route is audited (the independent review of Beta 1.6) | 2026-11-15: the refusal writes `AUTH_PASSWORD_CHANGE_NOT_PENDING` with outcome DENIED, naming the factor checked and whether it was spent (an authenticator step is, a recovery code is not) and nothing that was typed; the status, the body and the recovery code left unspent are as they were, and the failure count is still cleared, as the 403 for an issued password clears it (`test_the_no_change_pending_refusal_is_audited_with_the_factor_it_checked`, `test_the_no_change_pending_refusal_says_a_recovery_code_was_checked_and_not_spent` and `test_the_no_change_pending_refusal_keeps_the_failure_count_reset_of_the_issued_password_refusal` in `test_issued_password_signin_pg.py`); whether the count should clear on a refusal is in Known residuals |
| **a purged exhibit kept what it said** | A purge deleted an exhibit's bytes and marked the row, and left its description, source address, extracted text and the full-text vector built from them, so a later reader of the register read the description and the address, and the search found the exhibit by words only its body held (independent review, AREA-03) | 2026-11-15: the update that marks the row also empties those four, in the scheduled sweep and in the out-of-schedule purge alike, and keeps the title, the hashes, the size, the media type and the storage key as the tombstone's name for it; a row whose delete the store refused is neither marked nor emptied (`test_exhibit_purge_empties_content_pg.py`); the custody route, which read the source address back from the append-only ACQUIRED row, withholds it once the exhibit is purged, so it holds for exhibits purged before this date too. Exhibits purged before this date are emptied the same way, once, by Alembic 0200 when the deployment upgrades: the description, the source address and the extracted text, then the vector (two statements, because the vector is rebuilt from the title whenever the other three change), on rows with `purged_at` set and on no other, with one summary audit event that holds a count and no value (`test_purged_exhibits_emptied_0200_pg.py`). 0200 cannot be undone: its downgrade changes nothing, and a backup taken before it still holds what it emptied. Whether the title should go too is a judgement to confirm (Open, CONFIRM THE JUDGEMENT) |
| **the purge preview was a plain hash** | A dry run's `preview` was the sha256 of every due item of the case, the ones above the caller included, so a caller could rebuild it from the items they were shown and learn that something was left out, or whether a remembered id was due, under a case whose withheld disclosure is NONE (independent review, AREA-01) | 2026-11-15: the preview is an HMAC-SHA256 of the same material under a subkey of the audit pepper, compared in constant time, and a real run is still refused unless it presents the dry run's preview. With no pepper a production dry run issues none and a real run is refused; rotating the pepper voids a preview not yet confirmed (`test_purge_preview_keyed_pg.py`, `test_purge_preview_binding.py`, `test_audit_hash.py`) |
| **the hold proof credited a retention** | The preservation check read a refused DELETE of the hold canary as the hold's, although an unexpired retention of any mode refuses one with the same words, and wrote "no retention" in its evidence without reading one, so a bucket with a default retention, or a canary that carried one, could show green for a store that does not enforce a hold (independent review, AREA-02) | 2026-11-15: the canary's retention is read back before the DELETE, by the first credential that may read one (the preservation account's own policy does not), and the check fails unless there is none; a held canary that carries one is passed over for a fresh one, and no credential able to read it is a failure that says so (`test_readiness_worm_probe.py`) |
| **a purge deleted markup a collector was attaching** | The purge deleted collected markup when no other live document named its key, a check that cannot see a document a collector had inserted and not yet committed, so the new document kept a key that pointed at nothing (independent review AREA-04; the inverse of F46) | 2026-11-15: the collector takes an advisory lock on the key before it puts the object and holds it to the end of its transaction, and the purge tries the same lock around its check and its delete and keeps the object, saying so in a warning, when it cannot have it (`test_document_raw_key_lock_pg.py`) |
| **a record cites what its reader may not see** | A capture, a call and a contact block are labelled at their own classification and can cite an exhibit, and a block its publisher's entity, labelled above them: an AMBER reader of an AMBER capture was given the id of the RED exhibit it cited, and every reader of an ATTRIBUTE proposal a block's parse raised was given the entity's id. The screenshot route then answered an exhibit above the caller 403, another case's 404 "no such capture" and a capture with none a third 404, and wrote a row for the first alone, so the status said what the id named (independent review ACCESS-02, ACCESS-05) | 2026-11-15: `element_gate.visible_element_ids` is the one answer to whether a reader may see a cited entity or exhibit, by their ceiling on the case, and `withhold_cited` answers every id it refuses as null in the capture, call and contact-block routes (a duplicate handed back included), in a proposal's payload and in the entity, tie or claim its accept wrote, which a reviewer may label above it (queue, accept, reject, defer); the impersonation list names, and counts, a block's publisher entity only at or below the reader's ceiling; the console names such an entity "an entity not visible to you". The screenshot route gates its exhibit with `gate_element`, so a hidden exhibit, another case's and a capture with none are one 404 with one AUTHZ_DENIED row after the same statements. No capture's, call's or block's labels are raised (`test_cited_ids_above_the_reader_pg.py`, `test_impersonation_names_no_publisher_entity_above_its_reader` and `test_an_accepted_proposal_names_no_element_written_above_its_reader` among them, `test_absent_element_work_pg.py` "a capture's screenshot", `test_triage_inbox_pg.py`, `test_ui_triage_inbox.py`) |
| **a grant by id names the colleague's labels** | A grant by address that the service refused was told one sentence that names no clearance and no compartment and was recorded as CASE_SHARE_REFUSED, but the same grant by user id, which is on the roster of every case the colleague is on, was told their clearance level, the compartment keys they lack or that they hold a live liaison assignment elsewhere, and nothing was recorded (independent review, ACCESS-01) | 2026-11-15: a grant by id is refused in the address's words (`routers/cases.SHARE_REFUSED`) and recorded as CASE_SHARE_REFUSED with `by` `user_id`, the id and the reason alone (`test_case_lifecycle_api_pg.py` `test_a_grant_by_id_is_refused_in_the_words_a_grant_by_address_is`, `test_a_liaison_holds_one_case_at_a_time`) |
| **a case id that names nothing** | A case the caller is not on met the gate and wrote an AUTHZ_DENIED row naming it, while a case id that named nothing was answered 404 inside `effective_labels`, after one read and with no row, so `GET /audit/events` showed which probe named a case (independent review, ACCESS-03) | 2026-11-15: `authorize_object` decides a case id that names nothing at the phantom's labels (decision 230), so it sends the same statements and writes the same row, naming the id asked about; only `failed_checks` differs, which the listing does not return (`test_a_case_that_names_nothing_pg.py`, `test_absent_element_gate.py`) |
| **a duplicate block above the caller** | Text submitted as a contact block that was parsed already in the case at labels the caller does not hold answered 400 "at a label you do not hold" where a duplicate they could see answered 201, and on an owner connection the hidden block was handed back whole (independent review, ACCESS-06) | 2026-11-15: it answers 201, as a duplicate does, with `already_parsed`, no id, no entries and one sentence that names no label, decided by the caller's own ceiling on any connection, and the console draws the sentence alone (`test_cited_ids_above_the_reader_pg.py` `test_a_block_parsed_above_the_caller_is_answered_as_a_duplicate_without_its_fields`, `test_ui_triage_inbox.py`). What it still says is under Known residuals |
| **a tie to an entity above the reader** | A tie labelled as its case is, joining an AMBER entity to a RED one, is drawn for no AMBER reader, but nine routes gated it at its own label only: an AMBER reader holding its id read its claims, its exhibits and its review history, retracted, dated or scored its claims against a hypothesis, cleared such a score, cited an exhibit for it, and accepted a proposed tie that named such an entity, writing a tie they could not read back. The routes that add a claim to a tie, correct, review or retire it gated its entities after its own label, so a tie with a hidden end sent more statements than a missing one (graph-edge-endpoints-not-gated; the second review of 2026-11-15) | 2026-11-15: a tie, and a claim on one, is gated at the tie's labels joined with its two entities' (`graph._tie_facts`, one statement whatever the id names, reading the entities' labels as facts); its claims, exhibits and review are read only when both entities are the reader's (`read._visible_edge`); a claim on it is scored or its score cleared (`ach.set_stance`, `ach.clear_stance`), and an exhibit cited for it (`evidence.link`), only when row security admits both entities as well as the tie, in the one statement a missing id is asked with; and an accept gates both entities a proposed tie names and refuses with one 409 for an entity above the reviewer, in another case or missing, before anything is written. A tie with a hidden end, a hidden tie, another case's and a missing id send the same statements, write the same row and get the same answer (decision 230) (`test_a_read_of_a_tie_to_an_entity_above_the_caller_is_the_missing_tie`, `test_a_claim_on_a_tie_to_an_entity_above_the_caller_is_the_missing_claim`, `test_a_stance_or_an_exhibit_on_a_tie_to_an_entity_above_the_caller_is_the_missing_one` and `test_a_proposed_tie_to_an_entity_above_the_reviewer_is_the_missing_entity` in `test_selectors_and_ties_above_caller_pg.py`, each with the RED entity at either end, and the twelve families of a tie to a hidden entity in `test_absent_element_work_pg.py`, the eleven that name a tie or a claim on one asked with the hidden entity at either end) |
| **a replaced claim counted as live** | Nine reads of the claims asked only whether a claim was not retracted, so a claim that a dated copy had replaced came back to life when the copy was withdrawn: the exhibit it carried went on backing the element (the canvas mark, the inspector's list, the register's counts and its backs-nothing filter, and the backs route), the claim could be retracted although `supersede_assertion` refuses it as history, it went on pinning its collected document against the retention sweep after its replacement was withdrawn, and a stance on it went on scoring in the ACH matrix and the report | 2026-11-15, the second review of Beta 1.6: each read asks both questions, `retract_assertion` refuses a replaced claim, a replaced claim no longer pins its document, and the matrix keeps a stance on a replaced claim as a stale row that scores nothing, which the owner is asked to confirm under Open (`test_a_replaced_claim_is_history_pg.py`, `test_every_read_of_a_live_claim_asks_both_questions.py`, `test_a_replaced_claim_does_not_pin_its_document_once_its_replacement_is_withdrawn`) |
| **what a mirror backup does not carry** | An exhibit lodged after 0139 reads its recorded object version, and a mirror to disk keeps bytes and not version ids, so evidence restored into a new store read as missing and raised an integrity alarm, and a preserved sample's retrieval read a version its store never had. The one recovery was an owner step that set every `storage_version_id` to NULL under the anchor trigger, which made reads take whatever was newest under a key and undid the pin for good, and nothing restored a preserved sample | 2026-11-15, on the owner's instruction to lay the piping for stores other than MinIO (decision 240): `scripts/restore_object_versions.py` puts the mirrored bytes into the new store after proving them (an exhibit's SHA-256 and BLAKE3 against its row and its hash-chained ACQUIRED row; a sample's ciphertext opening, under its own data key, to its size, SHA-256 and recorded SHA-1 and MD5), under a COMPLIANCE lock or a legal hold set in the put, reads them back by their own version id, and appends one `RESTORED` row (Alembic 0198 and 0199) that `core.evidence_current_version` and `lab.sample_current_preserved_version` resolve; nothing is rewritten and the version an object was lodged as stays on its row. It runs as the system role with a restore account of its own that can delete nothing and lift nothing, and the owner step is withdrawn from the runbook (`test_a_restore_records_the_new_version_in_a_chained_custody_row_and_an_audit_row` in `test_restore_pg.py`, `test_a_preserved_sample_restores_under_a_hold_and_reads_back_held` in `test_restore_samples_pg.py`, and against the dev MinIO `test_restore_into_a_fresh_locked_bucket_against_the_dev_minio` and `test_a_preserved_sample_restores_into_a_fresh_held_bucket_against_the_dev_minio` in `test_restore_live_pg.py`) |
| **merge set-aside comment** | The column comment on `deleted_by_merge` (0055) still said a self-loop, though decision 176 also sets aside a duplicate tie the person merging cannot read | 2026-11-15: the comment names both reasons (Alembic 0185, `test_the_merge_set_aside_column_comment_names_both_reasons_pg.py`); `MergeRecord.edges_self_loop_deleted` counts both by design, and the `NODE_MERGED` audit detail and the owner's notification (`edges_duplicate_folded`) tell them apart |
| **downgrades that print a key** | 0133, 0134, 0141 and 0147 failed on the unique key they rebuild with a raw unique violation whose DETAIL printed the duplicated key, which could be a selector value | 2026-11-15: each downgrade counts the keys that would collide and refuses before it changes anything, with `refusing to downgrade NNNN:` and the count in fixed words, naming no value; `db/README.md` gives queries that find the rows by id (`test_a_downgrade_that_cannot_rebuild_its_key_names_a_count_and_no_value_pg.py`) |
| **`search_path` carries over** | In 53 released migrations a session-wide `SET search_path` carried into later revisions of the same run | 2026-11-15: the 77 statements are `SET LOCAL search_path`, so every revision starts at the session's own path; a fresh schema is unchanged (`db/schema.sql` identical, and an upgrade one revision per process built the same schema as one run before the change) (`test_no_migration_sets_search_path_for_the_whole_session.py`) |
| **the heartbeat and the queues** | `collect.collector_heartbeat` and the queues `core.embedding_pending`, `lab.yara_compile_job` and `ingest.batch` were writable by the request role, which 0179 left because they are not configuration, so through SQL a forged heartbeat could turn the readiness row `collector_split` green, the embedding queue could be emptied, a compile job deleted or stalled, and a batch created under any key or pointed at another object | 2026-11-15: all four are read-only to the request role. The collector writes its heartbeat as the system role; a request's upload, claim or retraction queues its embedding through definer triggers, and an item embedded on demand is written on the EMBEDDINGS system connection after the route's readability check; a compile is queued only through `lab.yara_compile_enqueue`, for a version that exists; and a batch is created only through `ingest.batch_accept`, by a caller holding the HMAC of the key's secret, on a live key, at its digest's content address (Alembic 0187 to 0190, `test_queues_read_only_pg.py`). The tables beside them stay under Known residuals |
| **a case's retention date and governance text** | The request role updated ten columns of `core."case"` because its routes wrote them as that role (0178), so through SQL it could move a case's retention date, rewrite its governance text, change its status or a policy switch without the route's gate or its audit row | 2026-11-15: the request role updates no column of a case and takes no row lock on one; the edit, the status move and the policy switches, with a relax approval's spend in the same transaction, are written on a system connection (`SystemPurpose.CASE_RECORD`) after the route's gate, refusals and step-up, and their audit rows name the caller (Alembic 0186, `test_case_record_system_writes_pg.py`) |
| **rls-6, case membership** | The request role, even with no session bound, read every `iam.case_assignment` row: who holds which role on which case | 2026-11-15: a request-role connection reads its own assignments, whatever the case's labels, and the team of every case it may open, which the roster already shows that case's members, and one bound to nobody reads none; the live socket's per-delivery checks and the sample origin's ticket redemption are bound before the gate reads, and the Lab reads a case's leads through `iam.case_leads`, which answers a member, an exempt caller and a holder of `sample.read` for a case within their reach (Alembic 0191 and 0192, `test_rls_case_assignment_pg.py`, `test_case_assignment_readers.py`) |
| **lifting a hold is one person (decision 193)** | Lifting a legal hold, an exhibit's, a case's or a collected document's, was one person with a written reason | 2026-11-15, decided by the owner (decision 229): every lift takes a second person who could lift it too and is cleared for what it releases, approving with a fresh second factor; the one who asked spends the approval once, within 72 hours, on the hold as it stood when they asked, both are judged again when it is spent, and the database refuses a lift no consumed approval accounts for, whoever writes the row (Alembic 0193 to 0195; `test_a_hold_is_lifted_only_with_a_second_persons_approval`, `test_a_case_hold_is_lifted_only_with_a_second_persons_approval` and `test_a_document_hold_is_lifted_only_with_a_second_persons_approval` in `test_hold_lift_two_person_pg.py`, `test_the_database_refuses_a_hold_lift_without_a_consumed_approval` and its case and document twins in `test_hold_lift_guard_pg.py`; Decisions the owner took) |
| **conversations above everyone assigned (decision 177)** | A RED conversation in an AMBER case could be flagged or minimised only by someone cleared for it; where nobody assigned was, nobody could, and nothing said so, at closure or anywhere else | 2026-11-15, decided by the owner (decision 231): the conversations nobody assigned can minimise are counted live and never named, closing is never refused over them, the closure is recorded with a count and a TLP tier, every Security officer is told and lists the cases under Oversight, Minimisation gaps (`comms.minimise.oversee`, Alembic 0196), the case's Lead investigators are told as its withheld-disclosure setting allows, readiness has `conversations_minimisable`, and a cleared Lead investigator assigned to the case minimises them through the unchanged route (`test_a_conversation_above_everyone_assigned_is_counted_and_the_case_still_closes`, `test_the_gap_names_no_conversation_or_label_to_anyone_below_it`); the record and the notices follow the closing reply, so under NONE its time says nothing (`test_the_closing_reply_does_the_same_work_whatever_the_gap`). Decision 177 stands: nobody acts above their own labels |
| **mail with no trusted stamp (http_ui-007)** | An `Authentication-Results` header was believed on where it sat, above a `Received` line naming a trusted MTA, and a sender writes both: a message handed over as a file recorded `dkim=pass` for a domain of the sender's choosing and proposed it as a durable DOMAIN selector | 2026-11-15: a header is believed only under a valid `X-NocTORnal-Stamp` that the deployment's own mail server adds under `NOCTORNAL_MAIL_STAMP_KEY`, and its authserv-id must still be a trusted MTA host; with no key or no stamp every such header is the sender's claim, and 0197's `auth_basis` marks the verdicts recorded before (decision 234, `test_review46_auth_results.py::test_a_forged_received_and_a_forged_authentication_results_above_it_are_not_believed_without_a_stamp`, `test_mail_stamp.py`). The `Received` boundary of an unstamped message stays open (Known residuals) |
| **co-participation weights** | A weight divides by the room's raw size, hidden members included, and the register read that as a way for a reader to difference out that someone they cannot see is in a room (a room of two AMBER identities and one RED one weighs 0.5 where a two-person room weighs 1.0) | 2026-11-15, decided by the owner ("weighting should be your best estimate"): the weight stays over the room's roster, because the premise did not hold. A participant row carries no labels and its row policy is its conversation's, so whoever may read a conversation lists every participant of it (`GET /comms/contact-graph`), the RED identity's handle included, and the weight is computable from that list under NONE, PRESENCE and COUNT and is one figure for every reader of the room. Dividing by the visible size would have created the channel. What a reader could tell apart was a handle resolved above them from an unresolved one: dropped where the other was drawn or counted, it was the handle that was neither. It is now drawn and left out as an unresolved handle, and counted with them under NONE and PRESENCE (decision 232; `test_a_weight_divides_by_the_roster_the_reader_can_list`, `test_a_weight_is_one_figure_for_every_reader_of_the_room`, `test_a_weight_never_depends_on_how_many_participants_resolve_above_the_reader`, `test_an_oversized_room_is_sized_by_the_roster_the_reader_can_list`, `test_the_roster_of_a_readable_conversation_is_readable_whole`, `test_a_handle_resolved_above_the_reader_draws_as_an_unresolved_handle`, `test_hidden_identities_are_counted_with_the_unresolved_under_none_and_presence`, `test_the_counts_stay_separate_under_count` and `test_toggling_include_unresolved_does_not_reveal_which_handle_resolves_above_the_reader`, in `test_coparticipation_roster_pg.py`) |
| **the withheld count of the connection log** | The connection log reported how many rows of the whole log the caller's clearance hid, and the sequence numbers of the rows it showed and Verify the chain's row count gave the same figure, so a reader below a label who polled and subtracted learnt when hidden egress rows arrived and roughly how many | 2026-11-15: the listing says only whether any row of the whole log is withheld (`some_withheld`), and a reader it withholds anything from is given no sequence number and no chain length; a broken chain is still reported to every reader with the sequence number of its first broken row. What is left is one bit: the flag turns on at the first row hidden from a reader, and moves after that only when a label, a compartment or the reader's clearance changes (decision 238, `test_review46_ledger_withheld_pg.py`, `test_egress_admin_http_pg.py`, `test_review46_ledger_footer_ui.py`) |
| **the failed-sign-in email** | A password shaped like an address (`Hunter2@home.net`) was stored as typed, every other typed value and every `ip_hash` was an unsalted sha256, and both could be guessed by anyone who could read the audit log | 2026-11-15: a failed sign-in records the length and `email_hmac`, a keyed hash, of what was typed and never the value, an account's own address included (decision 237), and every `ip_hash` is a 16-byte HMAC, both under `NOCTORNAL_AUDIT_PEPPER`, without which production refuses to start (`test_audit_hash.py`, `test_an_address_shaped_password_for_an_unknown_account_is_never_stored_as_typed`, `test_missing_audit_pepper_is_refused`); rows from before stay as they were (Known residuals) |
| **stopping or editing a watch** | A watch could be made and then never changed: no route and no control stopped it or edited it, so a mistyped pattern or a noisy keyword meant a new watch under a new name, and the watches of a closed case kept raising hits that nobody could quieten | 2026-11-15: `POST /cases/{case_id}/collection/watches/{watch_id}/stop` and `.../resume`, and `PATCH /cases/{case_id}/collection/watches/{watch_id}`, stop, resume and edit a watch behind the two checks that making one sits behind (the global `watch.manage`, then `collection.read` on the case, under `collection.config`), and the Collected tab's rows carry Stop or Resume and Edit for a collection manager. Any collection manager on the case may change any watch of it. Stop is a flag and never a delete, and it works on a closed case, because the collector keeps matching a closed case's watches; resume and edit are content writes a closed case refuses. An edit replaces a list whole, cannot change the source, kind or target, obeys the rules a new watch does through the same helpers and writes by compare-and-set. Each change is audited (`WATCH_STOPPED`, `WATCH_RESUMED`, `WATCH_EDITED`) with where the watch is aimed or counts, never a term or the name, and that row is the only record of who and when, because no column holds it. A poll stamps a watch's last hit only when that watch raised one (`test_collection_watch_change_pg.py`, `test_collection_watch_rules.py`, `test_watch_change_ui.py`, `test_closed_case_read_only.py`, `test_last_hit_at_moves_only_on_a_watch_that_hit` in `test_collection_pg.py`) |
| **watch patterns** | A pattern that did not finish was described in the code and the register only in part: the CPU limit that usually ends a spinning pattern, the 8 second wall clock, the run's budget, the retry on every run and the unreported slow pattern were not written where an owner reads | 2026-11-15: wording. The `watch_regex.py` docstring and constant comments, the run warning, `docs/04-collection.md` and the manual now state the three clocks and that a stopped pattern is tried again, at the same cost, until its watch is edited or stopped; the two things not closed (a flaw in the interpreter's matcher, a slow pattern that finishes inside its limits and is not reported) are stated in `watch_regex.py` (`test_watch_regex_wording.py`, `test_a_stopped_pattern_is_tried_again_on_the_next_run` in `test_review46_watch_regex_pg.py`) |
| **hidden and missing differ in time and in the audit log** | A hidden element met the gate and wrote an AUTHZ_DENIED row, and an id that named nothing was answered after one read with no row: paired medians 12.9 to 15.3 ms apart on this host (tie create, merge, entity correction), 97.6 against 79.1 ms on the first count | 2026-11-15, decided by the owner (decision 230): an id that names nothing, or names another case's element, is gated at the phantom's labels (`element_gate.facts_or_phantom`), which nobody can hold, so it sends the statements a hidden element sends and writes the same row, on every route that names an element, the proposal accept and the exhibit legal hold included (`test_a_missing_id_runs_the_same_statements_as_a_hidden_one`, `test_a_missing_id_writes_the_denial_row_a_hidden_one_writes`, `test_no_router_answers_an_absent_element_before_its_gate`). Paired median differences after, 60 pairs each with a 95 per cent bootstrap interval (`apps/api/tests/measure_absent_cost.py`): tie create -2.1 ms [-5.2, +0.7], merge -0.7 [-3.3, +4.2], entity correction +0.7 [-3.9, +4.3]; before, on the same host, +15.3 [+13.7, +16.9], +13.5 [+10.4, +14.7] and +12.9 [+11.4, +14.9]. What remains is under Known residuals |
| **YARA in the worker** | The worker image installed yara-x only when it was built with `--build-arg NOCTORNAL_EXTRAS=yara`, so a plain build scanned no sample with a rule, and nothing proved the engine could run under the worker's confinement | 2026-11-15: the Dockerfile's default extra is `yara` and the one compose build passes `${NOCTORNAL_EXTRAS-yara}`, so only an explicitly empty value builds without it; yara-x is installed from `requirements-yara.txt` by the sha256 of its wheel; the selftest child compiles a one-rule test and scans with it, and `sample_static_analysis` fails when an installed engine cannot; in a worker run with the compose file's confinement the selftest, a compile and two scans passed at 2 GiB, 512 MiB and 256 MiB of address space; CI's Production image builds job builds the image with and without the extra (`test_the_dockerfile_defaults_to_the_yara_extra`, `test_the_compose_build_passes_yara_by_default_and_honours_an_empty_value`, `test_the_production_image_installs_yara_from_the_hash_pinned_file_before_the_editable_install`, `test_the_selftest_scans_with_yara_when_it_is_installed`, `test_the_row_fails_when_the_engine_is_installed_but_the_workers_selftest_scan_failed`, `test_the_ci_image_job_asserts_yara_x_in_the_built_image_and_its_absence_under_the_opt_out`) |
| **unpinned inputs** | The CI workflow's own containers were pulled by tag, the installers upgraded pip to whatever PyPI served that day, and the Dockerfile installed whatever `gnupg` Debian shipped that day (F34 depends on its version) | 2026-11-15: every container the CI workflow runs is pinned by the digest the compose files pin for its tag, and the Pinned images resolve job asks the registries about the workflow's pins too and fails on an image pulled by tag or a tag with two digests; both installers and CI install pip from `requirements-pip.txt` by version and hash (pip 26.2.2); the Dockerfile installs gnupg at one Debian version, `GNUPG_VERSION`, refuses a build whose gnupg or gpg is another upload, and a new CI job builds the image on every push (`test_every_image_the_ci_workflow_pulls_is_pinned_by_digest`, `test_the_ci_digests_are_the_ones_both_stacks_pin`, `test_the_ci_pinned_images_job_reads_the_workflow_itself`, `test_the_pip_pin_is_one_hashed_file_and_both_installers_install_from_it`, `test_the_dockerfile_pins_gnupg_by_exact_version_and_checks_it`, `test_the_ci_image_job_builds_the_dockerfile`) |
| **a working-bucket delete on a versioned bucket** | The deletes of collected markup and of a sample's working copy named no version, so on a versioned bucket (AWS organisations often enforce versioning) they added a delete marker and returned success while every byte stayed retrievable by version id, and the purge recorded a destruction that had not happened | 2026-11-15: a working-bucket delete removes every version by its id when the store answers that it only added a marker, and raises when a version stays, so the purge keeps the document; an unversioned bucket is deleted as before (`objectstore.versions.delete_working_object`; `test_collection_rawstore.py`: `test_a_delete_on_a_versioned_working_bucket_removes_every_version`, `test_a_working_delete_that_leaves_a_version_raises`, `test_the_live_versioned_working_bucket_keeps_no_version_after_a_delete`) |
| **a denied raw read is a missing object** | A raw ingest batch or a collected page whose read the store refused for any reason (a denied read, a missing bucket) was reported as missing, with the sentence that tells a partner to resend, and `exists()` answered "nothing there" on any refusal, so a purge on a denied HEAD recorded collected markup as gone while its bytes stayed | 2026-11-15: only a key the store says is not there is missing; a denial, a missing bucket or a store that does not answer propagates from a read and from `exists()`, so the purge keeps the document (`test_collection_rawstore.py`: `test_a_denied_read_is_not_a_missing_object`, `test_exists_does_not_swallow_a_refusal_so_a_purge_never_reports_nothing_there`) |
| **rls-6 (part)** | The request role read every session's token hash, binding hash, address and client, and every break-glass justification | 2026-10-08: the request role reads no session's token hash, binding, address or client and no break-glass justification, which it reaches only through `iam.session_by_token` and through `iam.break_glass_justification` for the grant's holder and `break_glass.review` (Alembic 0177, `test_rls_iam_columns_pg.py`), while `iam.case_assignment` stays readable because its readers include unbound rechecks and reads of other people's roles (Known residuals) |
| **sealed columns outside the accounts table** | The request role read as ciphertext or a keyed hash a persona's sealed credential and forum session, an ingest key's HMAC, a lookup provider's sealed key, a download ticket's hash and a sample's sealed data key | 2026-10-08: the request role is granted none of a persona's sealed credential or session, an ingest key's HMAC, a lookup provider's sealed key, a download ticket's hash or a sample's sealed data key, and the API reads generated columns for whether one is held and definer functions for a provider's key, a sample's key and the ticket spends (Alembic 0180, `test_sealed_columns_pg.py`) |
| **unpolicied configuration tables** | The request role could write the egress, collection, retention, ingest-key, lookup-provider, Jira, screening and embedding configuration tables, which no row policy filters, without the step-up and the audit the administration routes apply | 2026-10-08: the egress profiles, routes and destinations, sources, personas, collection authorities, retention rules, embedding indexes, ingest keys, lookup providers, Jira destinations, screening lists and each person's delivery settings are read-only to the request role, their routes write them on a system connection after the same gate, step-up and audit, and an ingest key's use is stamped only by a definer handed the key's secret (Alembic 0179 and 0182, `test_configuration_read_only_pg.py`) |
| **hold and purge columns, and soft-delete tables** | The request role could update an exhibit's `legal_hold`, `purged_at`, `retention_until` and `is_worm_locked` and a case's `legal_hold` and `retention_until`, and delete from case tables the product only marks | 2026-10-08: the request role updates only `storage_version_id` on an exhibit and the ten case columns its routes write, so holds, purges, exhibit retention dates and WORM locks are the system role's alone, and it deletes from no policied table but the four a request deletes from (Alembic 0178, `test_case_material_writes_pg.py`); a case's retention date and governance text stayed writable by SQL until 2026-11-15 (Alembic 0186, above) |
| **definer functions answer for any id** | `SELECT last_value` on `lab.sample_access_id_seq` read the Lab custody ledger's volume | 2026-10-08: `lab.sample_access.id` is drawn by a definer trigger and neither runtime role holds its sequence, so `last_value` no longer reads the Lab ledger's volume (Alembic 0175, `test_sample_access_sequence_pg.py`), and the fact functions still answer any id, by design (decision 141) |
| **idle window at the binding** | `iam.rls_actor` checked a session's absolute expiry and not its 30-minute idle window | 2026-10-08: `iam.rls_actor` binds a session only inside its 30-minute idle window as well as before its absolute expiry (Alembic 0174, `test_rls_idle_binding_pg.py`) |
| **`notify.enqueue` text** | A caller bound to a live session could send arbitrary text to any eligible recipient, as itself, with a pending mail delivery | 2026-10-08: a request-role caller raises only the seven kinds a request raises, at their own priority, as itself, with a subject and summary in one of the product's templates and about a case it may act on (Alembic 0181, `test_notify_templates_pg.py`) |
| **the audit log's append policy** | The insert policy on `audit.event` admitted any row, so a bound user who was not on a case could append a state-bearing row naming it | 2026-10-08: the request role appends a state-bearing row (an ACH stance or status, a tie review, a triage verdict, attachment or category correction, an account event, a screening pass, a break-glass invocation) only naming one of its cases, or case-less as an `ingest` row under a global `ingest.manage`, and refusals and every other row append as before (Alembic 0176, `test_rls_audit_append_pg.py`) |
| **LIAISON is not single-case** | docs/05 says a liaison holds one case, and one liaison account could be assigned to several | 2026-10-08: granting LIAISON to an account that already holds a live LIAISON assignment on another case is refused in `CaseService._grant` (live is the gate's own test, no end or an end still to come, and a lock per account makes two simultaneous grants meet), a re-grant on the same case still moves the end date, and a share by address is refused without saying why and recorded as CASE_SHARE_REFUSED (`test_case_lifecycle_api_pg.py`). An account that already held two live assignments is under Known residuals |
| **a second permission check in a handler** | `GET /admin/embeddings/gaps` made a global-permission check in the handler, outside the gate, and its 403 wrote no AUTHZ_DENIED row | 2026-10-08: `GET /admin/embeddings/gaps` asks for the global `collection.read` as a second gate dependency after `embedding.manage`, so a refusal is the gate's 403 with its AUTHZ_DENIED row instead of an unrecorded one from the handler (`test_embedding_admin_pg.py`) |
| **refusals are recorded as SUCCESS** | An AUTHZ_DENIED audit row was stored with outcome SUCCESS, so a filter on outcome missed it | 2026-10-08: every row `deps.audit_auth_event` writes (AUTHZ_DENIED, AUTH_SESSION_REJECTED, RLS_BINDING_FAILED, SESSION_BINDING_REFUSED, CASE_SHARE_REFUSED) is stored with outcome DENIED, as are the sign-in router's cookie, recovery-code and password-change refusals, the PII reveal and search refusals, and the AUTHZ_DENIED and AUTH_FAILED rows of the egress and Telegram persona scripts; no reader of the log filters on outcome, and rows written earlier keep SUCCESS (`test_authz_denied_outcome_pg.py`) |
| **`real_name` on an identity** | The graph service accepted `attrs.real_name` on an IDENTITY entity, which goes against invariant 2 in spirit though not in the schema | 2026-10-08: the graph service refuses a `real_name` attribute on an IDENTITY at creation and at correction, whatever its case, separators or width and at any depth, in one sentence that names no value, while a PERSON may carry one and a correction that leaves it out removes an older one (`test_identity_real_name_pg.py`) |
| **retiring an entity with a hidden tie** | The refusal to retire an entity with a tie above the caller was the same under NONE, PRESENCE and COUNT, so under NONE it still said that such a tie exists | 2026-10-08, decided by the owner: a retirement over a tie the caller cannot see is refused whole under every setting, and under `withheld_disclosure = NONE` the refusal is `HIDDEN_TIES_REFUSAL_NONE`, which names no tie, clearance or compartment, while PRESENCE and COUNT keep today's sentence and the live-merge guard answers in the same words as the tie guard under each (`test_hidden_ties_none_pg.py`; Decisions the owner took) |
| **no console control for a hold** | The console had no control to place or lift a legal hold on an exhibit or on a case; only the collected document's had one | 2026-10-08: an exhibit's card has a Place or Lift the legal hold button and the case header a Hold button and dialog, each asking for a written reason and a sign-in from the last 15 minutes as the collected document's does, offered only where the register or case record says `may_hold`, with a LEGAL HOLD chip for every reader (`test_hold_controls_ui.py`, `test_legal_holds_http_pg.py`) |
| **a hold cannot reach into a delete in flight** | A case hold entered while a purge ran waited for the exhibit being destroyed at that moment, and its own answer did not say what the purge destroyed while it waited | 2026-10-08: the case hold's answer and audit row say what a purge or sample rejection destroyed while the hold waited, counted over what the holder may see; a delete already running is still not stopped, and every item after it is kept (`test_legal_holds_http_pg.py`) |
| **the purge's own answer** | The real run's response and its tombstone totalled what the sweep acted on, exhibits above the caller included | 2026-10-08: a real purge answers with the counts, warnings and tombstone ids of what the caller may see, as the dry run does, and the tombstone still totals everything destroyed (`test_retention_visible_answer_pg.py`) |
| **report counts (decision 179)** | Only the exhibit figure of a report followed the case's withheld-disclosure setting; the entity, relationship and matrix counts were exact under PRESENCE, and under NONE the statement said nothing had been withheld when something had | 2026-10-08: the builder passes the case's setting into `Redaction`, so entities, relationships, exhibits and the hypothesis matrix's evidence are stated as the number under COUNT, as some under PRESENCE and not at all under NONE, and a statement never says nothing was withheld when something was (`test_report_redaction_statement.py`, `test_report_withheld_figures_pg.py`) |
| **reports and the destination's ceilings** | `POST /report/release` judged SMTP, webhook and Jira on the caller's typed ceiling only, so it allowed a release that the drain then refused | 2026-10-08: a release is judged against the lower of the typed ceiling and the one configured for SMTP, webhook (`NOCTORNAL_*_CEILING`) or Jira (the destination under `NOCTORNAL_JIRA_CEILING`), the audit row and answer name it, and an unreadable value refuses (`test_release_ceiling_pg.py`) |
| **hold rows name no exhibit** | A hold or lift wrote an audit row with `object_id` NULL, so an officer could not tell which exhibit was held | 2026-10-08: hold and lift audit rows carry the exhibit (`object_type` evidence, `object_id`) or, for a case hold, the case (`test_legal_holds_http_pg.py`) |
| **upload answers** | An unknown classification answered 403 where 400 is right, and a store that was down answered a raw 500 after about 18 seconds, with an audit row saying an object was orphaned when none was stored | 2026-10-08: an unknown classification is a 400 naming the valid ones, the store pool gives up in seconds, an unanswered store is a 503 with Retry-After, and an orphan audit row is written only when a request may have landed (`test_upload_answers_pg.py`) |
| **the destruction meter** | Lifts and dry runs shared the `retention.destroy` meter, and a request refused for a stale sign-in used it too | 2026-10-08: lifts, dry runs and real purges each have a meter of their own (`retention.lift`, `retention.dry_run`, `retention.destroy`), spent after the global gate so a stale sign-in spends none (`test_retention_visible_answer_pg.py`) |
| **F55** | Dead letters and ingest records attached to no case were swept by nothing | 2026-10-08, decided by the owner: dead letters and ingest records attached to no case join `scripts/retention_sweep.py` (dry run by default, `--apply` with the same declared authority and named account, never scheduled), a record attached to a case stays that case's, and `retention_sweep_current` counts them (`test_retention_sweep_unattached_pg.py`; Decisions the owner took) |
| **a sample download does not call the egress gate** | `SampleService.download` never called `can_egress`, while the production of an exhibit containing attacker markup does | 2026-10-08, decided by the owner: a sample download is not an egress, and the one-shot ticket (F22) stands as its design (Decisions the owner took) |
| **a junk credential is still read** | A request carrying any Bearer value or a session cookie was read, and spooled to disk up to the route's cap, before the route judged it, in an API container with no size-limited `/tmp` and behind a proxy with no body limit | 2026-10-08: the API's `/tmp` is a 1 GiB size-limited tmpfs and the sample origin's is 64 MiB, and Caddy refuses a body over 256 MiB on the five multipart routes with a 413, so a request carrying a junk credential cannot write more than the tmpfs holds (`test_proxy_upload_limits.py`) |
| **the socket says ready early** | The live socket answered ready before the hub's LISTEN was registered, so a write in that gap was missed, and the tests waited a second to cover it | 2026-10-08: the live socket answers ready only after the hub's LISTEN is registered and closes 1013 when it cannot register it, and the socket tests no longer wait a second (`test_live_ready_after_listen.py`) |
| **no compression of the console** | Caddy did not compress `/ui`, so the console went out whole | 2026-10-08: Caddy compresses `/ui` with gzip or zstd and nothing else, so the console's three files go out as 0.67 MiB where 2.27 MiB went (`test_proxy_upload_limits.py`) |
| **the case list at 375 px** | The case list page scrolled sideways by 280 to 390 px on a phone-width window | 2026-10-08: the case list no longer scrolls sideways at a phone width, because the scroll box around a table is now the containing block of the visually hidden heading inside it (`test_console_phone_width.py`) |
| **`parse` with a case id** | `POST /ingest/batches/{id}/parse` with `case_id` always answered 403, because no case role carries `ingest.manage` | 2026-10-08: `POST /ingest/batches/{id}/parse` takes no case and answers 400, naming the attach route, if it is sent one; a record goes into a case by attach on `ingest.replay` (`test_rls_ingest_pg.py`) |
| **console tab** | A pane chosen while a case was opening was undone when the open ended on the Graph | 2026-10-08: a pane chosen while a case opens is kept, the open ends on the Graph only when nobody chose, and a deep link no longer takes a chosen pane back (`test_console_tab_choice.py`) |
| **a notice raised after it was queued** | A drain judged a case at its current labels, but an element raised after its notification was queued was not rechecked | 2026-10-08: the outbox drain judges a notice at the labels its element has now (the exhibit of an integrity alarm, the entities of a merge or its approval, the sample of a detonation or a screening, a feed record) composed with its case's, and revokes a delivery whose recipient no longer dominates them (`notifications.element_rows_sql`, `deliverable_predicate`; `test_notifications_pg.py`, `test_jira_transport_pg.py`) |
| **the MISP floor can fail open** | An unknown answer shape from MISP became NOT_FOUND with no TLP floor, and the floor read only the first 50 attributes | 2026-10-08: a MISP answer's TLP floor is read from every attribute and event it carries, and a shape the adapter does not read (a tag with no readable name, a response that is not the expected object) is unreadable and labelled RED, never NOT_FOUND with no floor (`test_lookup_adapters.py`, `test_lookup_results_pg.py`) |
| **the proxy's shutdown** | `stop()` did not wait for open tunnels, so the ledger's CLOSE rows could be lost on SIGTERM | 2026-10-08: a SIGTERM closes every tunnel with `proxy_shutdown`, waits up to 5 seconds for each connection to write its CLOSE row, then cancels what is left and waits 2 seconds more, and a tunnel authorised while the proxy is stopping is closed with it; the connection handler now runs as a task of its own, which it did not, so `stop()` had never waited for one (`test_egress_proxy_pg.py`) |
| **the pinned client's TLS check** | `pinned_http.open_connection` skipped the check that a TLS context verifies the certificate | 2026-10-08: `open_connection` refuses a TLS context that does not verify the certificate against the host name, before anything is resolved or dialled (`test_pinned_http.py`) |
| **a poll killed by SIGTERM** | A poll child killed by SIGTERM left its collection runs in the RUNNING state for good | 2026-10-08: a pass of `scripts/collection_poll.py` first marks the runs an earlier pass left RUNNING as FAILED with the class Interrupted, only when no runner holds their source's lock, counted as `interrupted` and not as the source failing (`test_collection_interrupted_pg.py`) |
| **a member mark's requeue** | `mark_member` committed before it took the persona lock, so a retry reported the wrong outcome | 2026-10-08: marking a chat as a member chat takes the persona's lock first, reads the chat again under it and runs the membership check under the same lock, so a busy persona refuses the act with nothing marked and the retry starts clean (`test_telegram_http_e2e.py`) |
| **a stopped persona resealed** | A stop racing the seal could leave a burnt persona holding a sealed forum session | 2026-10-08: `forum_session.seal_session` reads whether the persona is locked or burnt under the row lock it already takes, and a stopped persona is sealed nothing and loses what it held (`test_forum_member.py`) |
| **the lookup's raw body** | The raw body of a lookup answer was not scrubbed of live secrets, so a vendor that echoed the API key would have it stored | 2026-10-08: a lookup's answer is stored with every live secret removed from its body, in the forms a request and a JSON string spell it, and its hash is of what is stored (`test_lookup_results_pg.py`, `test_collection_hardening.py`) |
| **F53** | No route or console form created a watch | 2026-10-08: `POST` and `GET /cases/{case_id}/collection/watches` and the Collected tab's Add a watch form create and list a case's watches behind the global `watch.manage` and the case's own gate (refused on a closed case), with a source the creator can see, a typed chat id that the source reads for a Telegram chat, patterns that parse, and an audit row of counts and never terms (`test_collection_watch_create_pg.py`, `test_watch_create_ui.py`); stopping, resuming and editing a watch were built on 2026-11-15 (the Closed row, stopping or editing a watch) |
| **collection checks pass no compartments** | Collection's TLP checks passed no compartments, while the gate's collection rule refuses compartmented material and F43 deliberately polls compartmented sources | 2026-10-08, decided by the owner: a compartmented source keeps being polled and collection's ceiling stays label-only (Decisions the owner took) |
| **the archive tree count is not locked** | The tree's member count was read before the members were stored and not locked, so two archives of one tree expanded at the same moment could each pass the cap | 2026-10-08: the tree's count is read and its members stored under an advisory lock named by the tree's root, and a second archive of the tree waits up to the archive wall clock or records a pending gap that running static triage again clears (`test_lab_archive_pg.py`) |
| **archive limits the pre-check trusts** | `zip_preflight` trusted the end record's entry count, the parent's checks of a child's answer missed RecursionError and non-finite floats, and an archive answer was held about four times in the parent | 2026-10-08: a zip's central directory is counted by walking at most the member cap of records and not by the end record's claim, a child's answer that is nested too deeply or carries NaN or an infinity is a bad answer wherever a parent reads one, and the parent holds the answer once (`test_lab_archive_child.py`) |
| **an oversize sample is re-queued every pass** | A `worker_refused` for size re-queued the sample on every pass | 2026-10-08: a sample the isolated worker refuses for its size ends its run SKIPPED, with the worker's reported limit in the reason, and is not queued again (`test_analysis_interrupted_pg.py`) |
| **`yara_db.py` is outside the single client** | `scripts/yara_db.py fetch` ran `git` outside the one HTTP client, and the single-exit test did not scan `scripts/` | 2026-10-08: the single-exit test scans `scripts/` and refuses a script that starts `git` with a verb that talks to a remote, with `scripts/yara_db.py` the one allowance and its reason written beside it (`test_egress_single_exit.py`) |
| **the YARA fetch does not pin the head** | `fetch` followed the default branch of each of the nine third-party repositories in `yara/sources.json`, and nothing read the recorded commit back as a pin | 2026-10-08: a source in `yara/sources.json` can carry a `commit`, `fetch` pulls exactly that commit and refuses an unpinned source, `fetch --update` is the one way to follow the default branch and prints the commits to pin, and `stats` and `import` record whether the commit pulled is the pinned one (`test_yara_db_pin.py`); the manifest carries no pin until an operator runs `fetch --update` and reads the rules (Known residuals) |
| **the proxy's DSN naming the worker role** | `verify_proxy_environment` did not refuse an egress DSN naming `noctornal_worker`, a role that bypasses row security | 2026-10-08: the proxy refuses to start when its `DATABASE_URL` names `noctornal_worker` or `noctornal_app`, and in production when its database role is a superuser or bypasses row-level security (`test_egress_refusals.py`, `test_egress_role_privileges_pg.py`) |
| **`lab_triage` and an undeclared policy** | `scripts/lab_triage.py` printed `refused:` for an undeclared prohibited-content policy and exited 0, where an unusable setting exits 1 | 2026-10-08: `scripts/lab_triage.py` exits 1, printing `refused:`, when no prohibited-content policy is declared, as an unusable setting does (`test_analysis_runner.py`); the production loop then logs `exit=1` on every pass (Known residuals) |
| **unpinned inputs (part)** | The development compose file's images, the CI actions, pip and gnupg were pulled by tag, not pinned by digest | 2026-10-08: the development compose file's five images are pinned by digest and a test holds them to the table in `infra/production/README.md`, the checkout and setup-python actions are pinned to commits, and a CI job, Pinned images resolve, asks each registry about every image pinned in both compose files and the Dockerfile (`test_image_context_and_production_stack.py`, `test_dependency_pins.py`); the CI workflow's own containers, pip and gnupg stayed, and are pinned since 2026-11-15 (**unpinned inputs**, above) |
| **a missing hop count** | `NOCTORNAL_TRUSTED_PROXY_HOPS` at 0 or unset was neither refused nor reported in production | 2026-10-08: the readiness register has `proxy_hops_declared` (46 checks), which fails in production when `NOCTORNAL_TRUSTED_PROXY_HOPS` is unset or below one, says what that costs where the server is not told to trust the proxy, and is not blocking (`test_deployment_defaults.py`) |
| **bucket names have no shell default** | `$EVIDENCE_BUCKET`, `$INGEST_BUCKET` and `$SAMPLE_BUCKET` had no default in the `minio-init` script, though the code defaults them | 2026-10-08: `minio-init` defaults the three buckets to the names the code falls back to, and an empty value counts as unset (`test_deployment_defaults.py`) |
| **the volume name** | `release/install.sh` detected a new database volume by the fixed name `noctornal-prod_prod-pgdata` | 2026-10-08: both installers find the database volume by Compose's label as well as the documented name, and an engine that does not answer is `unknown`, never `new` (`test_deployment_defaults.py`) |
| **`Server: uvicorn`** | The `Server` header passed through Caddy to clients | 2026-10-08: Caddy takes the `Server` header off every answer on both hostnames, including its own errors and the websocket upgrade (`test_proxy_upload_limits.py`) |
| **ego and path past 5,000 entities** | The ego and path views built only the first 5,000 entities of a case by creation time and answered 404 for a centre outside them | 2026-10-08: the ego network is built outward from the entity and the path from both ends until they meet, under the projection's filters, so an entity anywhere in the case has an answer (114 of 120 sampled ego requests on the large case had answered 404); each stops at 5,000 entities, the ego network saying `truncated` and a path search that reached it answering 422, never "not connected" (`test_ego_path_from_the_centre_pg.py`) |
| **no statement timeout** | Nothing set a `statement_timeout` on request connections, so an abandoned request kept running | 2026-10-08: a request connection is opened with a `statement_timeout` (`NOCTORNAL_REQUEST_STATEMENT_TIMEOUT`, 120 seconds by default, from 5 to 3600, nothing switches it off), set against a case of 101,000 entities where the slowest request statement was 1.4 s alone and 20.8 s with fifty users; a request that hits it answers a 504 problem with a reference, and the system connections, the jobs and the migrations are not bounded (`test_request_statement_timeout_pg.py`) |
| **the register grows with the case** | The evidence register computed what each exhibit backs for every exhibit on every page | 2026-10-08: what each exhibit backs is counted for the page's rows only, and the case-wide "backs nothing" figure and filter ask each exhibit only whether it backs anything, stopping at the first live attachment, so a register request on the 15,300-exhibit case went from 5.8 s to 0.8 s cold with identical pages; the figure is still one pass over the case's exhibits (`test_evidence_register_page_pg.py`) |
| **duplicated rules** | About ten copies of the "is this production" check, about 14 tuples ordering the TLP levels beside `security/access.Tlp`, and a second `_refuse` existed | 2026-10-08: `config.is_production()` is the one reader of `NOCTORNAL_ENV` (ten modules and two scripts spelt it by hand; `db/migrations/env.py` keeps its own on purpose because it must decide before the package imports), `security.access.TLP_NAMES` is the one order of the five levels (fourteen tuples), and the compartment routes use the administration router's `_refuse` (`test_duplicated_rules.py`) |
| **test isolation** | Some tests skipped or failed depending on rows other suites left, 82 of 99 `client` fixtures repeated the same set-up, modules logged under two namespaces, and one test slept a second four times waiting for lock waits | 2026-10-08: the Telegram readiness, screening readiness, screening window and both ledger-anchor suites run in one rolled-back transaction with what other suites left hidden inside it, so none skips; every logger of ours is `noctornal.<name>`; the lock-wait suite polls `pg_stat_activity` instead of sleeping a second four times; still open: the 82 of 99 repeated `client` fixtures (`test_suite_isolation.py`, `test_log_namespace.py`) |
| **a connection for every request** | Each request opened a database connection, about 14 ms of a fixed cost of 45 to 55 ms a request | 2026-11-15: a request's own connection, the one `deps.get_conn` hands a route, comes from a pool (`db_pool`, `psycopg-pool`), on by default in production only, at most `NOCTORNAL_DB_POOL_MAX` (10) a process, with a 10 s wait and then a 503 problem with Retry-After, and no more waiting than leaves a fifth of the process's 40 worker threads free (`test_requests_beyond_the_threadpool_do_not_starve_those_holding_a_connection`); every connection that comes back is rolled back, reset with DISCARD ALL and read back against what it reported when new, and closed when anything differs, so no session or ticket binding, role, setting, advisory lock, LISTEN, prepared statement, cursor or temporary table reaches the next request, and CI runs the security suites again on the pool. The live channel, its sockets, the side connections and every system connection are still opened per use, and nothing was measured (decision 233; `test_db_pool_pg.py`, `test_db_pool_http_pg.py`, `test_db_pool.py`) |
| **F51** | Five tables were not under row-level security: the audit log, and the ingest records, victim credentials, dead letters and PII authorisations | 2026-10-03: all five are under policy and no table is deferred, 82 under policy (Alembic 0152 to 0155 and 0166 to 0169, docs/00 decisions 76, 143 and 151). `rls_registry.DEFERRED` is empty and a registry test names any table that carries labels and is in none of the three lists. Row security stays enabled and never forced (decision 143) |
| **F52** | The schema owner's password still reached the runtime services | 2026-10-02 to 2026-10-03: `POSTGRES_PASSWORD` and `NOCTORNAL_MIGRATION_DATABASE_URL` moved into `postgres-init.env` and `migrate.env`, each read by one service, and the API and every cron job refuse to run holding either; the rate limiter's Redis runs under an ACL and the limiter signs in as `noctornal_limiter`; every job script makes one refusal on a published credential (`release/secrets-upgrade/README.md`) |
| **F42** | Parse and analysis children were bounded, not isolated, so a parser exploit in a hostile sample or page was a compromise of the deployment | 2026-10-03: in production each hostile read (static triage, archive expansion, watch patterns, forum pages) runs in `analysis-worker`, a container with no secrets and no network, reached over a Unix socket (`infra/production/README.md`, Analysis worker). A local child remains for development, and `NOCTORNAL_ANALYSIS_LOCAL=1` keeps it in production on purpose, which the register reports |
| **F43** | Collected documents carried no compartments unless captured, so compartmented work was collected by hand | 2026-10-03: `collect.source` can carry compartments (Alembic 0163, 0164), every document a source collects carries them, and the readers, the notices, the Telegram path and the capture path honour them (docs/00 decision 78) |
| **F28** | A webhook signature carried no timestamp and no replay window | 2026-10-02: an opt-in signature v2 signs a timestamp with the body (`NOCTORNAL_WEBHOOK_SIGNATURE=v2`); docs/07 gives the receiver's replay window, the order to move in and a verifier (docs/00 decision 167). A receiver still on v1 stays replayable, which is the cost for anyone who does not opt in |
| **F35** | A persona could be created on a profile that cannot carry persona traffic | 2026-10-02: refused at creation, in the egress proxy's own sentence (`test_persona_creation_exit_pg.py`, decision 164) |
| **F36** | A run's warning lost a typed Telegram id | 2026-10-02: the ids this product's adapters write (`c:`, `g:`, `post:`, `member:`) are kept in a run's item label, and every other id still passes the redactor (`test_item_label_typed_ids.py`, decision 165) |
| **F37** | gpg's own fingerprint display did not parse in a contact block | 2026-10-02: whole hex groups are kept on `PGP_FPR` lines and the parser version is cb-2 (decision 166). Blocks parsed under cb-1 keep their reading and are in the untrusted-data table above |
| **F39** | The second person on a case's merge switch had no seasoning rule | 2026-10-02: the second person must have held `case.update` on the case for a window the deployment sets (`NOCTORNAL_RELAX_SEASONING_DAYS`, 7 by default, 0 off), checked when they approve and again where the approval is spent (docs/00 decision 169). Still open inside it: an administrator who resets a seasoned colleague's credentials and signs in as them is not covered |
| **F47** | Watches matched neither forum signatures nor Telegram chats | 2026-10-02: a post's signature is matched with reasons of its own, and a watch can target a Telegram chat by its typed id, which Alembic 0130 holds (decision 168). A watch is made from the Collected tab and the watches route (F53), and a chat watch with no term fires on every message (F54) |
| **F33** | The production compose file did not run the similarity pass, although readiness said to start one | 2026-09-25: an `embed-pass` service runs it in a loop of its own |
| **F34** | The production image carried no gpg, so every PGP check recorded NO_VERIFIER | 2026-09-25: the image installs the distribution's gnupg; a deployment attests it with `NOCTORNAL_GPG_PATCHED_AS` after checking its changelog |
| **SSRF through an egress proxy** | Persona traffic had no egress proxy, and a forward proxy resolves a name again, so the collector could not simply consult one | 2026-09-24: the egress proxy is the only way out of production (docs/00 decision 68, docs/20). It resolves each name once and dials only the admitted answers, with the same `egress_policy` functions the pinned client applies in development, and a chained exit receives the name, never an address this platform resolved |
| **SSRF rebinding** | `collection.fetch()` checked one DNS answer and connected with another, so a name answering public and then internal reached the internal address | 2026-09-23: each hop's name is resolved once and the socket goes to the address that was checked, while `Host`, TLS SNI and the certificate check stay on the name (`test_collection_ssrf_rebinding.py`) |
| **F2** | `REJECTED` samples were destroyed by default | 2026-09-22, decided by the owner (Decisions the owner took) |
| **F14** | Which roles may invoke break-glass was a guess | 2026-09-22, decided by the owner (Decisions the owner took) |
| **F16** | `victim_pii.reveal` was granted to no role | 2026-09-22, decided by the owner, migration 0062 (Decisions the owner took) |
| **F24** | The evidence store's upstream is archived | 2026-09-22, decided by the owner: stay on the pinned build; the register proves write-once (Decisions the owner took) |
| **sec-compartment-retirement** | The registry bound every compartment column (0059) and refused to drop or rename a key any row carried, with no product route to do either | 2026-09-23: `POST /api/v1/compartments/{key}/rename` moves a key everywhere in one transaction without changing who holds it, and `/retire` drops a key nothing carries and otherwise counts what does (`user.manage`, step-up, audited; Admin, Compartments). `test_compartment_lifecycle_pg.py` holds both |
| **F1** | A Telegram channel id and a user id could share one durable value | 2026-07-26, migration 0051: ids are namespaced `u:`/`c:`/`g:` and the Bot-API encoding is decoded arithmetically. The residual (a bare positive assumed to be a user) closed 2026-09-11: it is refused now, and `refusal()` names the typed forms. Rows written under the assumption are in the untrusted-data table above |
| **F15** | Ten Phase 4 and Phase 9 service defects, found by an adversarial pass | 2026-07-25, all fixed at the service |
| **F17** | The third adversarial pass: PGP status injection, the "encrypted" ZIP that was a plain ZIP, sample download with no label check | 2026-07-25. The rows those defects wrote are in the untrusted-data table above |
| **F18** | A sample download needed no clearance (the id `test_samples_pg.py` cites) | Closed: `download()` refuses without a clearance |
| **F19** | The hostile pass over Phases 5 and 8 found nine criticals, including a notification centre that never checked case assignment | 2026-07-26 |
| **F20** | The ACH matrix ranked an untested hypothesis top, and the warning that would have caught it could not fire | 2026-07-26 |
| **Approvals UI** | Phase 6 dual control had no analyst surface, so Merge was unreachable from a browser whenever it was on | 2026-08-10, Triage, Dual control |
| **Key ring** | A mismatched `NOCTORNAL_TOTP_KEK` made login answer 500, and the readiness check could not see it, because it verified the key decoded and not that it decrypted anything | 2026-09-11: `key_id` selects the key, the register opens stored secrets and counts, and a secret the ring cannot open is a failed sign-in (audit reason `totp_secret_unopenable`, the lockout counts it, 401 at login and 403 at a password change) |
| **The 2026-10-03 review** | 82 findings, 16 high, 25 medium and 41 low | 2026-10-07: 77 fixed, one fixed for credentials and stated for the rest (rls-6), four stated and not fixed. 2026-10-08: 78 fixed, rls-6 fixed apart from case membership, three stated and not fixed. Each finding's status is below, and what the fixes left is in Known residuals |
| **the application image and the proxy hops** | Caddy ran as uid 0 with a route out and a bridge shared with the database, Redis and MinIO; the hops to Postgres and Redis were plain text; `./tls`, with MinIO's `private.key`, was mounted into every application container | 2026-11-15: a CA of the deployment's own (`scripts/internal_tls.py`, name-constrained to `minio`, `postgres` and `redis`) signs one certificate per server, each key is mounted into its own server alone and the clients mount `tls/public`, which holds no key (`test_internal_tls_script.py`, `test_tls_hops_compose.py`); Postgres serves TLS 1.3 behind a `hostssl`-only hba file, Redis TLS 1.3 with no plain port, and production refuses a DSN without `sslmode=verify-full` or a `REDIS_URL` that does not check the server (`test_database_and_redis_transport_refusals.py`, `test_redis_limiter_acl.py`, `test_production_secrets_script.py`); Caddy runs as uid 10002 on `frontend` and `ingress` with no route out, ACME being `compose.acme.yml` (`test_tls_hops_compose.py`, `test_egress_topology.py`); the readiness row `internal_hops_encrypted` reads the live hops (`test_readiness_internal_hops.py`); decision 236. What it leaves is under Deployment, installers and backups |

### The 2026-10-03 review: its 82 findings at Beta 1.1

An adversarial review of the build at commit 718f92d (2026-10-03) kept 82 of 84
findings after a second reader tried to refute each: 16 high, 25 medium and 41
low, none critical. At Beta 1.1, 78 are fixed, one (rls-6) is fixed for account
credentials, session metadata and break-glass justifications and stated for case
membership, and three are stated and not fixed (evidence-chain-no-anchor, lab-6
and, narrowed, http_ui-007). A fixed finding that leaves something carries the
sentence here and an entry under Known residuals. Reproduction steps are not
published. On 2026-11-15 http_ui-007 was fixed by the mail stamp (Closed).

#### Row-level security and accounts

| Id | Severity | At Beta 1.1 |
|---|---|---|
| rls-1 | high | Fixed (Alembic 0132): merge history and the merge approvals are visible only where both entities are. |
| rls-2 | medium | Fixed (0134): a selector's key includes its labels, so the owner and the counters of a hidden row are never returned. |
| rls-3 | medium | Fixed (0133): a live tie's key includes its labels, so creating one says nothing about a hidden one. A merge over a duplicate the merger cannot read sets it aside and records it. |
| rls-4 | medium | Fixed (0141): the bytes of a hidden exhibit upload as novel bytes. |
| rls-5 | low | Fixed (0147): a conversation's external key is unique per labels. |
| rls-6 | medium | Fixed for credentials (0143), and for session metadata and break-glass justifications (0177): the request role cannot read the password hash, the sealed TOTP secret, its key id, the recovery hashes or the last counter, any session's token hash, binding, address or client, or any break-glass justification. Case membership was still readable by it at Beta 1.1; since 2026-11-15 it reads only its own assignments and the teams of the cases it may open (0191, 0192). |
| rls-7 | low | Fixed (0144): the request role cannot write step-up freshness, and a session guard confines the idle clock. |
| rls-8 | low | Fixed (0145): `notify.enqueue` answers only a bound caller, as itself. |
| rls-9 | low | Fixed: a node set's member list follows the case's disclosure setting. |
| rls-10 | low | Fixed: the documents give the registry's real count, 82 tables under policy and none deferred. |

#### Graph

| Id | Severity | At Beta 1.1 |
|---|---|---|
| graph-merge-ledger-and-approvals-leak | high | Fixed (0132 and the approval routes): hidden entities' ids and the merger's reason are not shown, and a hidden approval answers as a missing one. |
| graph-merge-no-element-label-gate | high | Fixed: merge and reversal check the entities' own labels, and a hidden entity answers as a missing one. |
| graph-selector-record-oracle | high | Fixed (0134): a hidden holder reads as no holder, on `POST /selectors`, `POST /nodes` and a label correction. |
| graph-edge-endpoints-not-gated | medium | Fixed: a tie to a hidden, other-case or unknown entity answers 404, and a retirement count no longer localises a hidden tie. A tie's claims, exhibits and review, retracting, dating or scoring a claim on it, clearing that score, citing an exhibit for it and accepting a proposed tie were still gated at the tie's own label; since 2026-11-15 each of these routes gates both its entities too (Closed: **a tie to an entity above the reader**). |
| graph-retracted-correction-stays-in-force | medium | Fixed (0136): a correction records the value it replaced, and retracting it puts that value back. |
| graph-assertion-claims-mutable-by-request-role | medium | Fixed: 0135 refuses UPDATE, DELETE and TRUNCATE of a claim to both runtime roles, and 0171 binds an INSERT. The worker role keeps what it holds (Known residuals). |
| graph-selector-index-drift | medium | Fixed (0138 and the writers): the index follows a corrected label, a retired and recreated entity and an accepted proposal. |
| graph-url-selector-keeps-credentials | medium | Fixed for the shapes known: a link's userinfo, credential-bearing query values and the `url:login:password` layout are refused or redacted on every path, and 0137 scrubbed what was stored. Shapes no pattern can see, and rows stored before 0137, are in Known residuals. |
| graph-unmerge-loses-ties-after-target-retired | low | Fixed: retiring the target of a live merge is refused (409), and a reversal reports the ties it restored and the ones left retired. |
| graph-unmerge-500-and-ties-to-merged-nodes | low | Fixed: a tie to a merged-away entity is refused (409), and a reversal that would duplicate a tie is a 409 naming the fix. |
| graph-valid-to-cannot-be-set-after-creation | low | Fixed: `PATCH` of an entity or a tie accepts `valid_to` as a correction that can be retracted. |
| graph-coparticipation-ignores-withheld-none | low | Fixed for the stated count, which is gone under NONE. A weight divides by the room's roster, which every reader of the room can list, so it carries nothing the roster does not, and a handle resolved above the reader is drawn and counted as an unresolved one (2026-11-15, decision 232; Closed). |

#### Evidence, retention, reports and the ledgers

| Id | Severity | At Beta 1.1 |
|---|---|---|
| evidence-hold-lift-below-label | high | Fixed: lifting a hold needs the lifter cleared for the exhibit, and a written reason; since decision 229 (2026-11-15) a second person cleared for it as well. |
| evidence-case-hold-unreachable | high | Fixed in the API (`POST /api/v1/retention/cases/{id}/legal-hold`) and, since Beta 1.1, from the Hold button in the case header. |
| evidence-purge-hold-race | high | Fixed: the purge runs one exhibit per transaction and reads the case hold again for each item. A delete already running is not stopped, and the hold's answer says what it destroyed while the hold waited. |
| evidence-report-case-raise-leak | high | Fixed: a report built below the case's label leaves out what was created before the raise, and says it was withheld. |
| evidence-integrity-anchors-mutable | medium | Fixed (0139, 0140): hashes, key, size and case are fixed when an exhibit is lodged, reads ask for its recorded version, and a missing or replaced version raises an integrity alarm. |
| evidence-audit-chain-forks | medium | Fixed (0149): both chains take their number inside the chain lock. |
| evidence-ingest-dedup-oracle | medium | Fixed: see rls-4. |
| evidence-due-leaks-hold-reason | medium | Fixed: the due list leaves out exhibits above the caller, and a hold's text goes only to `retention.manage` holders. |
| evidence-category-clock-outlives-case | medium | Fixed: a record is due at its case's date at the latest. |
| evidence-ledger-actor-time-forgeable | medium | Fixed (0150, 0151, 0169): the request role cannot name another user, date a row or draw the ledger sequences. |
| evidence-orphan-locked-object | low | Fixed: the row is inserted first and the object second, and a short write records `EVIDENCE_OBJECT_ORPHANED`. |
| evidence-reingest-after-purge-dropped | low | Fixed: bytes whose exhibit was purged lodge as a new exhibit. |
| evidence-report-release-in-app | low | Fixed: `in_app` and `model_host` answer 400. |
| evidence-unswept-unattached-and-dead-letter | low | Fixed (F55): dead letters and ingest records attached to no case join the operator-run sweep. |
| evidence-chain-no-anchor | low | Not fixed, stated: `/audit/verify` returns the tail it checked and says what a verification cannot see, and the anchor that would catch a cut tail is the operator's to record. |
| evidence-purge-stalls-audit-chain | low | Fixed: an unrelated audit insert does not wait on a purge. |

#### Egress, notifications and collection

| Id | Severity | At Beta 1.1 |
|---|---|---|
| egress-notify-address-list | high | Fixed (0148): a personal address is one plain address, and the drain refuses a stored list. |
| egress-rss-floor | medium | Fixed: a RED or AMBER_STRICT feed is refused, and the adopt step caps a feed's ceiling at AMBER. |
| egress-lookup-signoff-exposure | low | Fixed: raising a provider's exposure cancels a lookup that awaits sign-off. |
| egress-ledger-withheld-oracle | low | Fixed (2026-11-15): a reader below a label is told only that some rows are withheld, and the sequence numbers and the chain's length are withheld with them (Closed index). |
| collection-shared-exit | medium | Fixed: a persona is refused on an exit a public read uses. |
| collection-rss-doctype-bypass-utf16 | medium | Fixed: a feed whose decoded text holds a NUL is refused, which closes UTF-16 and UTF-32 with or without a byte-order mark. |
| collection-watch-regex-redos | low | Fixed: a pattern runs in a bounded child, in the isolated worker in production, and is stopped at its limit. |

#### The Lab

| Id | Severity | At Beta 1.1 |
|---|---|---|
| lab-1 | high | Fixed: with a live machine listed, a send that names none is refused. |
| lab-2 | low | Fixed: while a screening pass runs over a newly imported list, the sample's ticket, download, triage claim and sandbox send answer "no such sample". |
| lab-3 | low | Fixed: a record-only detonation is `PENDING` and notifies the named authoriser. |
| lab-4 | medium | Fixed: samples are due, and disposed of, by the purge. |
| lab-5 | low | Fixed: the origin split is asked before a ticket is spent. |
| lab-6 | low | Not fixed, stated (Known residuals). |

#### HTTP, sessions and the console

| Id | Severity | At Beta 1.1 |
|---|---|---|
| authz-session-revoke-bypass | medium | Fixed: a revoked session stays revoked, tested under concurrent requests. |
| http_ui-001 | high | Fixed: see rls-1. |
| http_ui-002 | high | Fixed: see graph-selector-record-oracle. |
| http_ui-003 | medium | Fixed: the row is inserted before the object, and a label below the case's floor or a NUL in a field is a 400. |
| http_ui-004 | high | Fixed: a bad bearer token writes no audit row, and replaying a revoked real token writes one row in all, however often it is replayed. |
| http_ui-005 | high | Fixed for JSON and form routes (a 1 MiB ceiling, chunked bodies included). An upload with a junk credential is still read to its cap, into a size-limited `/tmp` and under a 256 MiB limit at the proxy. |
| http_ui-006 | high | Fixed: a failed sign-in's email is 254 characters at most, and was recorded as typed only when it was shaped like an address; since 2026-11-15 it is recorded only as a keyed hash (Closed, the failed-sign-in email). |
| http_ui-007 | low | Narrowed, stated (Known residuals). Fixed 2026-11-15: only a header the mail stamp attests is believed, and 0197 marks the legacy rows (Closed). |
| http_ui-008 | low | Fixed: a binding to a node of another case, above the caller or unknown answers alike. |
| http_ui-009 | low | Fixed: a NUL in a parsed header no longer makes an e-mail unrecordable. |
| http_ui-010 | medium | Fixed: in production the first-run route does not exist without `NOCTORNAL_SETUP_TOKEN`, and needs the token when it is set. |
| http_ui-011 | medium | Fixed: raising a node-merge request checks the entities, and a hidden approval answers as a missing one. |
| http_ui-012 | low | Fixed: a change hint carries the labels of what changed, and the socket drops it for a reader below them. |
| http_ui-013 | low | Fixed: a hello that is not a JSON object closes 1008 without a logged error. |
| http_ui-014 | low | Fixed: a NUL, and a lone surrogate, in a JSON body is a 422. |
| http_ui-015 | low | Fixed: per-element lists take `limit` (at most 1000) and `offset`; the two case-wide exceptions are in CONVENTIONS.md. |
| http_ui-016 | low | Fixed in status and wording: a hidden element answers as a missing one. Since decision 230 a missing id also meets the gate and writes the same AUTHZ_DENIED row; the residuals are under Known residuals. |
| http_ui-017 | low | Fixed: a `#token=` link names the account it would sign in as and asks first. |

#### Infrastructure

| Id | Severity | At Beta 1.1 |
|---|---|---|
| infra-1 | medium | Fixed: `.dockerignore` leaves out every secret file the stack names, and local working notes. |
| infra-2 | high | Fixed: the documented backup writes outside the checkout, private from the first byte and encrypted in the pipe, and the dump names are ignored by the image and by git. |
| infra-3 | medium | Fixed: see http_ui-010. |
| infra-4 | low | Fixed: a boot refuses a request role named `noctornal` or `postgres`, and a connection as the owner or a bypassing role is refused when it is made. |
| infra-5 | low | Fixed: every service drops all capabilities and Caddy holds only `NET_BIND_SERVICE`. What stays is in Known residuals. |
| infra-6 | low | Fixed: Caddy sends Strict-Transport-Security, speaks TLS 1.3 only and redirects plain HTTP. |
| infra-7 | low | Fixed: the images of the production stack and of the development compose file are pinned by digest and the CI actions by commit. The CI workflow's own containers, pip and gnupg were pulled by tag, and are pinned since 2026-11-15 (Closed, **unpinned inputs**). |
| infra-8 | low | Fixed: Postgres runs with `log_parameter_max_length=0` and its error twin. |
| infra-9 | low | Fixed in `install.sh`, `launch.sh` and `start.sh`: `.env.local` is parsed as data. |
| infra-10 | low | Fixed apart from one argument (Known residuals). |
| infra-11 | low | Fixed: the cron loops stop on the stop signal after the pass in hand. |
| infra-12 | low | Fixed: every job script refuses a published credential, and the egress DSN's placeholder. |
| infra-13 | low | Fixed: `yara_db.py` does not follow a symlink in a pulled rule repository. |

---

## How to keep this file honest

Add an entry when you build something whose correctness rests on a judgement
rather than on a test. Move one to the Closed index when the judgement is
confirmed by somebody who can carry it, and record who, in
`docs/00-decisions.md`.

The failure mode this file prevents is the one docs/16 names: a system whose
assumptions live only in the heads of the people who wrote it ships, changes
hands, and then somebody discovers an assumption by breaking it.
