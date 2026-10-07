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
| **`KEY_MISMATCH` verifications** recorded before 2026-09-24 (F10a) | `comms.pgp_verification` where `outcome = 'KEY_MISMATCH'` and the last field of the stored `VALIDSIG` status line equals `claimed_fingerprint` | The parser compared the claim with the key that made the signature, which is a subkey whenever the vendor signs with one, so a genuine signature by the published key's subkey was recorded as a mismatch. It failed safe; the reading was false. | Verify each again. Do not edit the rows: the ledger refuses it. |
| **`CONFIRMED` bindings** upgraded before migration 0089 (F10b) | `SELECT cb.id FROM comms.channel_binding cb JOIN comms.pgp_verification v ON v.channel_binding_id = cb.id AND v.outcome = 'VERIFIED' AND v.attribution IS NULL WHERE cb.verification = 'CONFIRMED'` | Nothing tied the signing key to the binding's holder, so a guarantor's signed vouch could confirm a vendor's binding. | Verify each again, citing the contact block that ties the key to the holder. |
| **Verifications made with a gpg below the floor** (F10a, 2026-09-24) | `comms.pgp_verification.verifier_version` below 2.4.9 (2.4 series), 2.5.14, or 2.2.51, or any 2.3 | Those builds carry CVE-2025-68973 (the armour parser) or CVE-2022-34903 (status-line forgery); a distribution build may carry the fixes under an older number. | Confirm the build that made each, or verify again with a current one. Every production verification is `NO_VERIFIER` until the image installs gnupg. |
| **Records written under older rules** (L1 and L2, 2026-09-24) | Triage claims accepted before Alpha 6 with no `observed_at`; ATTRIBUTE claims readable below the material they came from, or attached across cases; captured documents cited by cases that share no compartment, which migration 0071 could not label | Each was written under a rule this release tightened, and nothing can recompute what was never recorded: an observation date, or the lock every citing case's readers hold. They are counted by the readiness rows `triage_claims_dated`, `triage_claims_within_labels` and `captured_documents_compartmented` | `python scripts/legacy_records.py` lists them per case. An analyst decides each: raise an entity, retract a claim, or file the capture again under the right case. An analyst gives a claim its date by superseding it (the inspector's Date this claim); nothing writes a date onto a recorded claim (docs/00 decision 170) |
| **Contact blocks parsed under cb-1 with a gpg-spaced PGP line** (F37, 2026-10-02) | `comms.contact_block` where `parser_version = 'cb-1'` and an entry has `selector_type = 'PGP_FPR'` with a 20-character `durable_value` | The parser cut the value at the first run of two spaces, so a fingerprint copied from gpg kept 20 of 40 hex characters; a CLAIMED proposal may carry the truncated value, the line cannot confirm a key, and the block is not paired with the same text parsed later | Nothing re-reads a stored block: parse the text again in a case of its own and reject the old proposal. Do not edit the rows |
| **Telegram ids recorded from a bare positive number** before 2026-09-11 | `core.selector` and `comms.channel_binding`, `TELEGRAM_ID` | A bare positive id was assumed to be a user (`u:`), so an MTProto channel observed as a bare number shares a row with a same-numbered user. The normaliser refuses a bare positive now, but nothing can recompute a type that was never observed. | `scripts/telegram_bare_ids.py` lists them per case. Confirm each against its source and re-record typed (`c:<id>`) where a channel is wearing a user's row. |
| **Credentials that stayed after 0137** (2026-10-07) | `core.assertion.rationale` where an accepted proposal copied its context; `collect.document` text; `core.selector` e-mail rows read out of the userinfo of a link that is not http or https; URL rows of the `url:login:password` layout written before that shape was refused | 0137 scrubbed URL selectors, entity labels, proposals, extraction rows and a correction's `prior_value`, and does not touch a claim's recorded rationale (invariant 5), the captured text or the audit detail | The queries under Known residuals at Beta 1 list them. Removing one is an owner decision |
| **Forks in the audit and custody chains from before 0149** | The audit and custody rows at or below the boundary 0149 recorded | Alpha 7a's concurrent writers forked both chains. Verification reports them as legacy and they do not break `intact`; a fork above the boundary is a break | Nothing: they are history, and the log is append-only |

---

## 🔴 CHANGE LIKELY

Nothing the 2026-09-22 review found is open here. The owner decided F2,
F14, F16 and F24 that day, and F3 was reclassified as an accepted cost (it
was never a defect: the register already refuses on it). Each decision, and
what was built to hold it, is in the section after the next two. F35, F36 and
F37 closed on 2026-10-02, and F51 and F52, the two items this section carried
at Alpha 8, are closed at Beta 1 (table at the end).

What is open is in the two sections that follow. The first says what became of
each finding of the 2026-10-03 review. The second is every gap the fixes, the
independent re-verification and the release reviews found and left, organised
by area. Read the second before reporting a weakness: a residual named there
is known, and by this file's own definition each one is CHANGE LIKELY unless
its entry says it is an accepted cost or a judgement to confirm.

---

## The 2026-10-03 review at Beta 1

An adversarial review of the build at commit 718f92d (2026-10-03), each
area's findings put to a second reader who tried to refute them, kept 82 of
84: 16 high, 25 medium and 41 low, none critical. Seven independent readers
then re-ran every reproduction against the merged code, and the fixes that
followed were checked again by the release reviews. At Beta 1, 77 are fixed,
one (rls-6) is fixed for account credentials and stated for the rest, and
four are stated and not fixed. A fixed finding that leaves something carries
the sentence here and an entry under Known residuals. Reproduction steps are
not published.

### Row-level security and accounts

| Id | Severity | At Beta 1 |
|---|---|---|
| rls-1 | high | Fixed (Alembic 0132): merge history and the merge approvals are visible only where both entities are. |
| rls-2 | medium | Fixed (0134): a selector's key includes its labels, so the owner and the counters of a hidden row are never returned. |
| rls-3 | medium | Fixed (0133): a live tie's key includes its labels, so creating one says nothing about a hidden one. A merge over a duplicate the merger cannot read sets it aside and records it. |
| rls-4 | medium | Fixed (0141): the bytes of a hidden exhibit upload as novel bytes. |
| rls-5 | low | Fixed (0147): a conversation's external key is unique per labels. |
| rls-6 | medium | Fixed for credentials (0143): the request role cannot read the password hash, the sealed TOTP secret, its key id, the recovery hashes or the last counter. Case membership, session metadata and break-glass justifications are still readable by it (Known residuals). |
| rls-7 | low | Fixed (0144): the request role cannot write step-up freshness, and a session guard confines the idle clock. |
| rls-8 | low | Fixed (0145): `notify.enqueue` answers only a bound caller, as itself. |
| rls-9 | low | Fixed: a node set's member list follows the case's disclosure setting. |
| rls-10 | low | Fixed: the documents give the registry's real count, 82 tables under policy and none deferred. |

### Graph

| Id | Severity | At Beta 1 |
|---|---|---|
| graph-merge-ledger-and-approvals-leak | high | Fixed (0132 and the approval routes): hidden entities' ids and the merger's reason are not shown, and a hidden approval answers as a missing one. |
| graph-merge-no-element-label-gate | high | Fixed: merge and reversal check the entities' own labels, and a hidden entity answers as a missing one. |
| graph-selector-record-oracle | high | Fixed (0134): a hidden holder reads as no holder, on `POST /selectors`, `POST /nodes` and a label correction. |
| graph-edge-endpoints-not-gated | medium | Fixed: a tie to a hidden, other-case or unknown entity answers 404, and a retirement count no longer localises a hidden tie. |
| graph-retracted-correction-stays-in-force | medium | Fixed (0136): a correction records the value it replaced, and retracting it puts that value back. |
| graph-assertion-claims-mutable-by-request-role | medium | Fixed: 0135 refuses UPDATE, DELETE and TRUNCATE of a claim to both runtime roles, and 0171 binds an INSERT. The worker role keeps what it holds (Known residuals). |
| graph-selector-index-drift | medium | Fixed (0138 and the writers): the index follows a corrected label, a retired and recreated entity and an accepted proposal. |
| graph-url-selector-keeps-credentials | medium | Fixed for the shapes known: a link's userinfo, credential-bearing query values and the `url:login:password` layout are refused or redacted on every path, and 0137 scrubbed what was stored. Shapes no pattern can see, and rows stored before 0137, are in Known residuals. |
| graph-unmerge-loses-ties-after-target-retired | low | Fixed: retiring the target of a live merge is refused (409), and a reversal reports the ties it restored and the ones left retired. |
| graph-unmerge-500-and-ties-to-merged-nodes | low | Fixed: a tie to a merged-away entity is refused (409), and a reversal that would duplicate a tie is a 409 naming the fix. |
| graph-valid-to-cannot-be-set-after-creation | low | Fixed: `PATCH` of an entity or a tie accepts `valid_to` as a correction that can be retracted. |
| graph-coparticipation-ignores-withheld-none | low | Fixed for the stated count, which is gone under NONE. A weight still divides by the room's raw size (Known residuals). |

### Evidence, retention, reports and the ledgers

| Id | Severity | At Beta 1 |
|---|---|---|
| evidence-hold-lift-below-label | high | Fixed: lifting a hold needs the lifter cleared for the exhibit, and a written reason. |
| evidence-case-hold-unreachable | high | Fixed in the API (`POST /api/v1/retention/cases/{id}/legal-hold`). The console has no control for it (Known residuals). |
| evidence-purge-hold-race | high | Fixed: the purge runs one exhibit per transaction and reads the case hold again for each item. A delete already running is not stopped (Known residuals). |
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
| evidence-unswept-unattached-and-dead-letter | low | Not fixed, stated (F55). |
| evidence-chain-no-anchor | low | Not fixed, stated: `/audit/verify` returns the tail it checked and says what a verification cannot see, and the anchor that would catch a cut tail is the operator's to record. |
| evidence-purge-stalls-audit-chain | low | Fixed: a four-exhibit purge took 4.1 seconds while an unrelated audit insert waited 0.0. |

### Egress, notifications and collection

| Id | Severity | At Beta 1 |
|---|---|---|
| egress-notify-address-list | high | Fixed (0148): a personal address is one plain address, and the drain refuses a stored list. |
| egress-rss-floor | medium | Fixed: a RED or AMBER_STRICT feed is refused, and the adopt step caps a feed's ceiling at AMBER. |
| egress-lookup-signoff-exposure | low | Fixed: raising a provider's exposure cancels a lookup that awaits sign-off. |
| egress-ledger-withheld-oracle | low | Fixed apart from one count: the withheld figure is one number for the whole log (Known residuals). |
| collection-shared-exit | medium | Fixed: a persona is refused on an exit a public read uses. |
| collection-rss-doctype-bypass-utf16 | medium | Fixed: a feed whose decoded text holds a NUL is refused, which closes UTF-16 and UTF-32 with or without a byte-order mark. |
| collection-watch-regex-redos | low | Fixed: a pattern runs in a bounded child, in the isolated worker in production, and is stopped at its limit. |

### The Lab

| Id | Severity | At Beta 1 |
|---|---|---|
| lab-1 | high | Fixed: with a live machine listed, a send that names none is refused. |
| lab-2 | low | Fixed: while a screening pass runs over a newly imported list, the sample's ticket, download, triage claim and sandbox send answer "no such sample". |
| lab-3 | low | Fixed: a record-only detonation is `PENDING` and notifies the named authoriser. |
| lab-4 | medium | Fixed: samples are due, and disposed of, by the purge. |
| lab-5 | low | Fixed: the origin split is asked before a ticket is spent. |
| lab-6 | low | Not fixed, stated (Known residuals). |

### HTTP, sessions and the console

| Id | Severity | At Beta 1 |
|---|---|---|
| authz-session-revoke-bypass | medium | Fixed: a revoked session stays revoked, tested under concurrent requests. |
| http_ui-001 | high | Fixed: see rls-1. |
| http_ui-002 | high | Fixed: see graph-selector-record-oracle. |
| http_ui-003 | medium | Fixed: the row is inserted before the object, and a label below the case's floor or a NUL in a field is a 400. |
| http_ui-004 | high | Fixed: a bad bearer token writes no audit row, and replaying a revoked real token writes one row in all, however often it is replayed. |
| http_ui-005 | high | Fixed for JSON and form routes (a 1 MiB ceiling, chunked bodies included). An upload with a junk credential is still read to its cap (Known residuals). |
| http_ui-006 | high | Fixed: a failed sign-in's email is 254 characters at most, and is recorded as typed only when it is shaped like an address (Known residuals). |
| http_ui-007 | low | Narrowed, stated (Known residuals). |
| http_ui-008 | low | Fixed: a binding to a node of another case, above the caller or unknown answers alike. |
| http_ui-009 | low | Fixed: a NUL in a parsed header no longer makes an e-mail unrecordable. |
| http_ui-010 | medium | Fixed: in production the first-run route does not exist without `NOCTORNAL_SETUP_TOKEN`, and needs the token when it is set. |
| http_ui-011 | medium | Fixed: raising a node-merge request checks the entities, and a hidden approval answers as a missing one. |
| http_ui-012 | low | Fixed: a change hint carries the labels of what changed, and the socket drops it for a reader below them. |
| http_ui-013 | low | Fixed: a hello that is not a JSON object closes 1008 without a logged error. |
| http_ui-014 | low | Fixed: a NUL, and a lone surrogate, in a JSON body is a 422. |
| http_ui-015 | low | Fixed: per-element lists take `limit` (at most 1000) and `offset`; the two case-wide exceptions are in CONVENTIONS.md. |
| http_ui-016 | low | Fixed in status and wording: a hidden element answers as a missing one. The time it takes and the audit row differ (Known residuals). |
| http_ui-017 | low | Fixed: a `#token=` link names the account it would sign in as and asks first. |

### Infrastructure

| Id | Severity | At Beta 1 |
|---|---|---|
| infra-1 | medium | Fixed: `.dockerignore` leaves out every secret file the stack names, and local working notes. |
| infra-2 | high | Fixed: the documented backup writes outside the checkout, private from the first byte and encrypted in the pipe, and the dump names are ignored by the image and by git. |
| infra-3 | medium | Fixed: see http_ui-010. |
| infra-4 | low | Fixed: a boot refuses a request role named `noctornal` or `postgres`, and a connection as the owner or a bypassing role is refused when it is made. |
| infra-5 | low | Fixed: every service drops all capabilities and Caddy holds only `NET_BIND_SERVICE`. What stays is in Known residuals. |
| infra-6 | low | Fixed: Caddy sends Strict-Transport-Security, speaks TLS 1.3 only and redirects plain HTTP. |
| infra-7 | low | Fixed for the production stack, whose images are pinned by digest. The development compose file, the CI actions, pip and gnupg are not (Known residuals). |
| infra-8 | low | Fixed: Postgres runs with `log_parameter_max_length=0` and its error twin. |
| infra-9 | low | Fixed in `install.sh`, `launch.sh` and `start.sh`: `.env.local` is parsed as data. |
| infra-10 | low | Fixed apart from one argument (Known residuals). |
| infra-11 | low | Fixed: the cron loops stop on the stop signal after the pass in hand. |
| infra-12 | low | Fixed: every job script refuses a published credential, and the egress DSN's placeholder. |
| infra-13 | low | Fixed: `yara_db.py` does not follow a symlink in a pulled rule repository. |

---

## Known residuals at Beta 1

What the fixes, the re-verification and the release reviews found and left,
by area. Each entry says what is true, what it costs and what would close it.
An entry marked "decision" records a call the owner may want to make
differently.

### Access control and row-level security

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| rls-6 (part) | The request role, even with no session bound, can still read every `iam.case_assignment` row (who holds which role on which case), `iam.session` (`token_hash`, `rls_binding_hash`, `ip`, `user_agent`) and `iam.break_glass.justification`. The credential columns of `iam.app_user` are closed (0143). `token_hash` is a sha256 of a 256-bit random token and the binding proof is derived from the raw token, not from that hash, so neither opens a session; what is disclosed is who works which case and from where. It takes a statement injected into a request. 0109 made the IAM plane read-only to the request role instead of filtered, because the policies read it on every request. | A column-level REVOKE of the session and break-glass columns with definer functions for the legitimate readers; filtering `iam.case_assignment` needs its readers moved to definer functions first. Each is a migration. |
| sealed columns outside the accounts table | The unbound request role can read as ciphertext or a keyed hash: `collect.collection_account.secret_ciphertext` and `session_ciphertext`, `ingest.api_key.secret_hmac`, `ingest.provider.secret_ciphertext`, `lab.download_ticket.token_hash`, and, for a bound caller with no assignment, `lab.sample.data_key_ciphertext`. No plaintext follows without the key encryption key or the pepper, which live in the process environment, and the persona key is held only by the collector in production. | A column-level REVOKE with definer readers for the length and null checks the API makes. A migration. |
| unpolicied configuration tables | The request role can write egress destinations, routes and profiles, `collect.source`, `core.retention_rule`, `ingest.api_key`, `notify.jira_destination` and similar tables, and no row policy filters them. One statement injected through a session could add an egress route or shorten a retention rule without the step-up and the audit the administration routes apply. | Move the writes to a system connection and revoke them from the request role, as 0109 did for the accounts plane. |
| hold and purge columns, and soft-delete tables | `noctornal_app` holds table-level UPDATE on `core.evidence` and `core."case"`, so a statement injected as that role can set an exhibit's `legal_hold` false, its `purged_at`, `retention_until` or `is_worm_locked`, and a case's `legal_hold` or `retention_until`. The database refuses a row that is both held and destroyed (0142) and fixes an exhibit's hashes, storage key, version id and case (0140); nothing guards `legal_hold` going to false. The request role also holds DELETE on soft-delete-only case tables and UPDATE on columns the application never writes as that role. The same class as F52 was: a process holding the request role's credentials can do what the application refrains from. | Narrow the request role's UPDATE and DELETE to the columns and tables the application writes as that role, or move those columns behind the system role by trigger, as 0140 did for the anchors. |
| definer functions answer for any id | `iam.case_facts`, `iam.element_facts` and `iam.countersign_blocked_by` answer the labels and the administration metadata of any id, without content. That is by design (decision 141). `SELECT last_value` on `lab.sample_access_id_seq` reads the Lab ledger's volume. | Not proposed for the facts; the sequence could be revoked as 0169 did for the two ledgers. |
| idle window at the binding | `iam.rls_actor` checks a session's absolute expiry and not its 30-minute idle window. The HTTP layer refuses first, so this needs a raw token and direct access to the database. | Check the idle window in the function. |
| session clock | The request role may move its own session's `last_seen_at` forward by up to five minutes past the database's clock (`CLOCK_SKEW` in 0144, stated there as intended: it keeps an API host with a fast clock from failing every request). | None proposed. |
| `notify.enqueue` text | A caller bound to a live session can send arbitrary text to any eligible recipient, as itself, with a pending mail delivery. 0145 stops it being sent as anyone else and stops it forging delivery rows; it does not limit what a bound account may say. | A kind and template allowlist inside the function. A migration. |
| the audit log's append policy | The insert policy on `audit.event` admits any row, so a bound user who is not on a case can append a state-bearing row naming it (a triage verdict, a category correction, ACH history, a report hypothesis note), and the readers that take the newest row by object id (`triage_state`) then read it. Attribution holds, because the row names the planter. Needs SQL as the request role. | Require the case term (`case_id = ANY(iam.rls_cases())`) or `ingest.manage` in the append policy for those actions. Not for refusals: an honest refusal names a case the caller cannot read. |
| LIAISON is not single-case | docs/05 says a liaison holds one case; one liaison account can be assigned to several. An assignment with no end is refused (decision 185). | Refuse a second live assignment of a LIAISON. |
| a second permission check in a handler | `embeddings.py` makes a global-permission check in the handler, outside the gate, and its 403 writes no AUTHZ_DENIED row. | Move it into the gate. |
| refusals are recorded as SUCCESS | An AUTHZ_DENIED audit row is stored with outcome SUCCESS (`http/deps.py`), so a filter on outcome misses them. | Store DENIED. |
| `real_name` on an identity | The graph service accepts `attrs.real_name` on an IDENTITY entity, which goes against invariant 2 in spirit though not in the schema. | Refuse the key. |
| development without row security | On an owner connection (development, a single-role deployment) the layout lists hidden entities and an ACH stance on a hidden claim answers 200. Under the production role both hold. | None: the request role is the control. |

### Graph, merges and selectors

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| label correction after a retraction | A label correction asks which selector types other entities hold only with the caller's labels. A retraction that restores a label passes none, so the lookup is not made there; a retraction never refuses, so nothing is told. The narrow cost is that the restored label of an entity that owns no index row for its own label (a duplicate of a value another entity holds) is not indexed under that holder's type. | None proposed. |
| merge set-aside (decision 176) | While a merge is live a set-aside tie is retired, so its claims count toward nothing and the survivor's own tie stands alone; reversing the merge restores them and nothing is destroyed. The column comment on `deleted_by_merge` (0055) still says a self-loop, and a merge record's `edges_self_loop_deleted` counts set-aside duplicates with the ties between the two entities; `edges_duplicate_folded` in the `NODE_MERGED` audit detail and the owner's notification tell them apart. A merge made through the service with no labels is refused as before. | Rewording the comment needs a migration. |
| conversations above everyone assigned (decision 177) | A RED conversation in an AMBER case can be flagged or minimised only by someone cleared for it; where nobody assigned is, nobody can. Whether a case's closure should look for a conversation no one on the team can minimise is not decided. | Decide it. |
| a refused reversal names that a later merge exists | The sentence says that a later merge the reader cannot see holds the reversal. That one bit cannot go without allowing the reversal the rule forbids, which would write old endpoints over ties a live merge owns. | None. |
| hidden and missing differ in time and in the audit log | The status and the sentence are one answer for a hidden element and a missing one. Medians over 40 interleaved in-process calls each were 97.6 ms against 79.1 ms (merge), 95.9 against 80.4 (tie create) and 81.1 against 66.5 (entity correction), and the gate writes an AUTHZ_DENIED row for the hidden id and none for the missing one. Doing the same work for a missing id would append a denial row for every id that names nothing, and the gap was measured with no network in between. | Decide whether a missing id should cost the same. |
| retiring an entity with a hidden tie | The refusal (`HIDDEN_TIES_REFUSAL`) is the same under NONE, PRESENCE and COUNT, so under NONE it still says that a tie above the caller touches the entity, while docs/14 U2 makes what is said about withheld material a per-case setting. Honouring NONE needs a decision between retiring over ties the caller cannot see and a refusal in words no different from any other. | Decide it. |
| co-participation weights | A weight divides by the room's raw size, hidden members included, so under NONE a room of two AMBER identities and one RED one weighs 0.5 where a two-person room weighs 1.0, and a reader who knows a room can difference a weight to learn that someone they cannot see is in it. The explicit count is gone under NONE; the weight is not. Migration 0030 already concedes that differencing is possible. | Divide by the visible size, at the cost of a figure that changes with the reader. |
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
| no console control for a hold | The console has no control to place or lift a hold on an exhibit or on a case. The one hold control is the collected document's (the document card, Place a legal hold). An exhibit is held with `POST /api/v1/retention/legal-hold` (`evidence_id`, `on`, `reason`) and a case with `POST /api/v1/retention/cases/{id}/legal-hold` (`on`, `reason`): both need `retention.manage` through the gate with a fresh second factor and a written reason of at least five characters whichever way the hold goes, and both write `LEGAL_HOLD_APPLIED` or `LEGAL_HOLD_LIFTED`. docs/08 says where an analyst finds this. | A control on the exhibit card and on the case header that calls the two routes. |
| lifting a hold is one person (decision 193) | Lifting a hold is one person with a written reason. A review suggested two people and the owner did not adopt it, so the code comments, this entry and the tests describe the single-person design. A lift below the material is refused: an exhibit's needs the lifter cleared for it, and a case-level lift needs a ceiling that covers every live exhibit, record, sample, lookup and cited collected document the case holds. | A two-person approval kind. |
| a hold cannot reach into a delete in flight | A case hold entered while a purge runs waits for the exhibit being destroyed at that moment, and that exhibit is destroyed. Every exhibit after it is read as held and kept, and the purge says so. The records, lookups and samples of a case share one short transaction that holds the case row `FOR SHARE`, so a hold entered during it lands after it; a destroying sample rejection holds the case row for its own delete. The hold's own answer does not say what the purge destroyed while it waited. | Have the hold response report it. |
| the tombstone and the out-of-schedule purge | `purge_due` marks each exhibit destroyed in the transaction that deleted it and writes the tombstones afterwards. If a tombstone cannot be written the exhibits are destroyed and marked and the error says how many; they are no longer due, so another purge does not write it. `purge_out_of_schedule` is still one transaction with the approval's spend, because the approval must be spent with the destruction, so a failure there after a store delete rolls the marks back, leaves the approval usable and the object gone. A destroying Lab rejection opens a second, system connection for the length of the delete, to hold the case row. | None proposed. |
| the purge's own answer | The purge dry run's totals and its withheld notice follow the case's setting, as the due list's do. The real run's response and its tombstone still total what the sweep acted on, exhibits above the caller included, so a caller who may run a real purge learns the count afterwards. A refused case-hold lift names nothing above the lead under NONE, but the refusal itself still differs from a lift that succeeds, which no wording can hide. | The same counts over the visible items for the real run. |
| report counts (decision 179) | Only the exhibit figure follows the case's withheld-disclosure setting. The entity and relationship counts, and the hypothesis matrix's count of withheld evidence, are still printed as exact numbers under PRESENCE, and under NONE the redaction statement reads "nothing has been withheld" when entities or exhibits were. | Carry the mode into `Redaction` and say "some" for all three figures. |
| reports and the destination's ceilings | `POST /report/release` judges SMTP, webhook and Jira on the caller's typed ceiling only. It ignores `NOCTORNAL_SMTP_CEILING`, `NOCTORNAL_WEBHOOK_CEILING`, `NOCTORNAL_JIRA_CEILING` and the Jira destination's own ceiling, which the drain applies, so a release is allowed that the drain then refuses. A lead read into a compartment can never release a report on a case that holds compartmented material. | Judge against the destination's ceiling at release. |
| a sample download does not call the egress gate | `SampleService.download` never calls `can_egress`, while the production of an exhibit containing attacker markup does. The download is the one authorised outbound act of a sample, behind a one-shot ticket (F22). | Decide whether a download is egress. |
| same bytes at other labels (0141) | The same bytes at different labels are separate exhibits, each with its own object, custody trail and register row. A case can therefore hold several copies of one file. The upload route takes a classification and no compartments, so lodging the same bytes into another compartment is reachable only through the service (capture, lookups, deception e-mails). | None proposed. |
| hold rows name no exhibit | A hold or lift writes an audit row with `object_id` NULL, and `/audit/events` omits `detail`, so an officer cannot tell which exhibit was held. | Carry the exhibit's id in `object_id`. |
| upload answers | An unknown classification answers 403 where 400 is right. A store that is down answers a raw 500 after about 18 seconds, with an audit row saying an object was orphaned when none was stored. | Validate the classification first; bound the store's timeout. |
| rows from before the key fix | An exhibit stored at a nested key before the key fix (development and test databases only, since no released build wrote them) stays unpurgeable. | Re-lodge it. |
| the destruction meter | Lifts and dry runs still share the `retention.destroy` meter, and a request refused for a stale sign-in uses it too, so after about three actions a lead waits roughly six minutes per action. Placing a hold no longer spends it (decision 192). | A meter per act. |
| F55 | Dead letters and caseless ingest records are swept by nothing (below). | The owner's decision. |

### Sessions, HTTP and the console

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| a junk credential is still read | The refusal before an upload is about a request that presents nothing. A request that carries any Bearer value or a session cookie is still read, and spooled to disk up to the route's cap, before the route judges it, because telling a live session from a junk one takes the database and the layer that refuses is deliberately free of it. The API container has no size-limited `/tmp` and the proxy sets no body limit, so one request can still write up to 256 MiB, bounded by the per-address request meter. | A size-limited tmpfs for `/tmp` on the API service and a `request_body` `max_size` in the Caddyfile for the upload routes. |
| the failed-sign-in email | A password that is itself shaped like an address (`Hunter2@home.net`) is not told apart from an address and is stored as typed. For everything else the sha256 prefix is unsalted, so a short typed secret can be guessed from it by anyone who can read the audit log. The same hashing already stands in `ip_hash`. | A keyed hash under a server secret the audit path does not hold today. |
| the socket says ready early | The live socket answers "ready" before the hub's LISTEN is registered, so a write in that gap is missed; the tests wait a second to cover it. | Answer ready after the registration. |
| no compression of the console | Caddy does not compress `/ui/*`: 2.35 MiB goes out where 0.66 MiB would. | An `encode` directive limited to `/ui/*`. |
| the case list at 375 px | The case list page scrolls sideways by 280 to 390 px on a phone-width window; the panes inside a case do not. The cause was not isolated. | Find it. |
| `parse` with a case id | `POST /ingest/batches/{id}/parse` with `case_id` always answers 403, because no case role carries `ingest.manage`; parse and then attach works. | Give the permission to a case role or drop the parameter. |

### Egress, notifications and collection

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| mail with no trusted stamp (http_ui-007) | `Authentication-Results` is believed only when its authserv-id is a trusted MTA (`NOCTORNAL_TRUSTED_MTA_HOSTS`), the topmost `Received` header was written by a trusted MTA and the header sits above every `Received` header (`deception.py`, `_auth_results_believed`). A message the receiving MTA never stamped (forwarded, exported, handed over as a file) carries only sender-written headers, and a sender who writes a forged `Received: by mx.<trusted host>` line and a forged `Authentication-Results` above it passes all three tests: the message then records `dkim=pass` for a domain of the sender's choosing and proposes it as a durable DOMAIN candidate. A lone header, and a header below a `Received` line, are still refused. The check is only as good as the border MTA removing inbound headers that carry its own authserv-id, which RFC 8601's security considerations name. Until it is closed, treat the recorded SPF, DKIM and DMARC of a message that did not arrive through the trusted MTA as the sender's claim. | A stamp the sender cannot compute (an HMAC header the MTA adds under a deployment key), or reading a verdict only for mail the capture path received from the MTA itself. |
| the withheld count of the connection log | The listing reports how many rows of the whole log the caller's clearance hides, and that count no longer moves with the route, event or window asked about. It is still one number for the whole log, so a reader below a label who polls it and subtracts successive answers learns when hidden egress rows arrive and roughly how many, though not which route, destination or case. | Report no count, only that some rows are withheld, which would also stop telling an officer how incomplete the view is for them. |
| collection checks pass no compartments | Collection's TLP checks (`collection.py` `_feed_floor_refusal`, `collection_authority.ceiling_refusal`, `telegram_service.py`) pass no compartments, while the gate's collection rule refuses compartmented material and F43 deliberately polls compartmented sources. | A decision on which is right. |
| a notice raised after it was queued | A drain judges a case at its current labels, but an element raised after its notification was queued is not rechecked. | Recheck the element. |
| the MISP floor can fail open | An unknown answer shape from MISP becomes NOT_FOUND with no TLP floor, and the floor reads only the first 50 attributes (`lookup_adapters.py`). What shapes a real MISP sends is not known (F27). | Fail closed on an unknown shape. |
| the proxy's shutdown | `egress_proxy.py`'s `stop()` does not wait for open tunnels, so the ledger's CLOSE rows can be lost on SIGTERM. | Wait for tunnels, bounded. |
| the pinned client's TLS check | `pinned_http.open_connection` skips `_refuse_unverifying`. Hardening only: its one caller passes a verifying context. | Call it. |
| a poll killed by SIGTERM | A poll child killed by SIGTERM leaves its collection runs in the RUNNING state for good. | Mark them on the next pass. |
| a member mark's requeue | `mark_member` commits before it takes the persona lock, so a retry reports the wrong outcome. | Take the lock first. |
| a stopped persona resealed | A stop racing the seal can leave a burnt persona holding a sealed forum session (`forum_member.py`). | Seal under the persona lock. |
| the lookup's raw body | The raw body of a lookup answer is not scrubbed of live secrets, so a vendor that echoed the API key would have it stored. Uncertain; no vendor is known to. | Scrub with the live key. |
| echoed secrets in a transformed form | The member walk removes the persona's password and session cookie exactly, in the plain, URL-encoded, form-encoded, base64 and (for markup) HTML-escaped forms, and only for a secret of at least six characters. A board that echoes a transformed form (hashed, case-changed, split across tags) is not caught. | None proposed. |
| the feed parser and a wide feed | A clean BOM-less UTF-16 feed that does not start with an XML declaration is refused too, and says why. No such feed is known. | None. |
| watch patterns | A stopped pattern costs 3 seconds more than it did (`STARTUP_S`). A pattern its CPU-time limit stops is reported as its time limit: the limit is set one second under its hard ceiling, so the kernel ends it with SIGXCPU, which the runner reads as a timeout (2026-10-07). A pattern that is slow but finishes inside its limits, and a defect in the interpreter's own matcher, are as the module's docstring says. | Wording. |
| F53, F54, F55 | No route or console form creates a watch (F53), a chat watch with no term fires on every message (F54), and dead letters and caseless ingest records are swept by nothing (F55). Entries below. | |

### The Lab and the isolated worker

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| lab-6 | A duplicate upload is refused (409) when the bytes are already held and accepted (201) when they are not. The refusal names no hash and says nothing more to a caller who may not see the existing sample, and nothing is stored in the prober's name, but the status code is still one bit across a compartment or label boundary: a holder of `sample.submit` who has a candidate file can learn whether this deployment already holds that exact file in a case they cannot see, which is the fact that somebody else is working the same intrusion. A probe that is accepted stores a sample, so each probe of a novel file leaves a row. This is inherent in content deduplication (`samples.py`, the comment at the dedupe branch, and `test_review46_duplicate_residual_pg.py` pin what still holds). | Store a second copy per label set, which for live malware is a decision for the owner. |
| a download ticket is burned before the refusal | A download ticket is spent, and a `SAMPLE_DOWNLOAD_TICKET_REDEEMED` audit row written, when it is presented, before the download checks the caller's live clearance and the sample's screening state. If the download then refuses, the holder gets "no such sample", the ticket is gone, and there is a REDEEMED row and no `DOWNLOADED` custody row, so the audit row reads as a redemption that served nothing. Spending first is deliberate (one statement makes the ticket one-shot); `lab.sample_access` is the record of what was served. | None proposed. |
| the archive tree count is not locked | The tree's member count is read before the members are stored and not locked, so two archives of one tree expanded at the same moment by two processes can each pass the cap, by at most one archive's member cap each. The count includes members that turn out to be duplicates, which errs toward refusing. | A lock. |
| archive limits the pre-check trusts | `zip_preflight` trusts the end record's entry count, so about 150 MiB of directory records are parsed before the count refusal; the parent's checks of a child's answer miss RecursionError and non-finite floats (exploiting this needs a compromised child); an archive answer is held about four times in the parent. | Bound the directory read; harden the checks. |
| an oversize sample is re-queued every pass | A `worker_refused` for size re-queues the sample on every pass. Depends on configuration. | Mark it skipped. |
| YARA in the worker | YARA was run in the Windows virtual environment's suites and not in the worker image: the only Linux build used had no yara-x. | Run the worker image's suite with the extra. |
| `yara_db.py` is outside the single client | `scripts/yara_db.py fetch` runs `git` outside the one HTTP client. It is an operator tool, and the single-exit test does not scan `scripts/`. | Scan `scripts/`. |
| the YARA fetch does not pin the head | `scripts/yara_db.py fetch` clones (or fast-forwards to) the default branch of each of the nine third-party repositories in `yara/sources.json`, depth 1. The commit pulled is recorded in `yara/fetch.lock.json`, but nothing reads it back as a pin. `import` never activates a rule set: a lab member adopts the imported version and a Security Officer who is neither of them activates it, so a changed rule reaches a reviewer and not a scan. | A `commit` field in `sources.json` that `fetch` will not move past without a flag. |
| the proxy's DSN naming the worker role | `verify_proxy_environment` does not refuse `NOCTORNAL_EGRESS_DATABASE_URL` naming `noctornal_worker` (BYPASSRLS, owns nothing). The schema owner is refused by `egress_proxy.start_checks`. Operator error only: the worker's DSN is not in a file the proxy reads. | A role check beside the ownership query. |
| `lab_triage` and an undeclared policy | `scripts/lab_triage.py` prints "refused:" for an undeclared prohibited-content policy and exits 0, where an unusable setting exits 1. | Decide the exit code. |

### The ledgers and the migrations

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| the tail anchor is the operator's | A verification cannot see the newest rows being cut off or the chain being rewritten and re-hashed by the owner. With an anchor held on a file the host cannot write, deleting the tail answers `ANCHOR_MISSING` and rewriting it `ANCHOR_REWRITTEN`; nothing records the anchor on its own. | Schedule `scripts/audit_verify.py --record` from a host that holds the file. |
| owner and worker rows | The owner and `noctornal_worker` keep whatever actor and time they supply, and their rows can sit slightly out of time order. An owner who inserts a row forked off a pre-boundary row would be counted as a legacy fork. `INSERT ... RETURNING seq, prev_hash` on a row the writer may read returns the newest seq and hash of the whole log (0169 documents it, and no application code asks for a row back). | None: they need owner rights. |
| downgrades that print a key | 0133, 0134, 0141 and 0147 fail on the unique index they rebuild when Beta 1 has stored two rows that differ only by labels, with a raw unique violation whose DETAIL prints the duplicated key, which can be a selector value. | Catch and name the count. |
| `search_path` carries over | In about 50 released migrations a session-wide `SET search_path` carries into later revisions of the same run. No effect today: a fresh and an upgraded schema are equal. | Use `SET LOCAL`. |
| 0134 holds a table | 0134 holds `core.selector` locked about 24 seconds per 300,000 rows; no faster form was found (dropping and rebuilding its trigram indexes around the rewrite measured 22 seconds against 20). | None. |

### Deployment, installers and backups

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| what a mirror backup does not carry | An exhibit lodged after 0139 reads its recorded object version, and a mirror to disk keeps bytes and not version ids, so evidence restored into a new MinIO reads as missing until the owner step in `infra/production/README.md` makes those exhibits read the latest version again. Preserved samples have the same limit. Nothing here restores either from a mirror. This was reasoned from S3 behaviour and the code, and not reproduced against a restored bucket. | A restore that sets the version ids it was given. |
| the backup was not restored on a fresh host | The documented dump and mirror commands ran as written, with the gpg alternative because `age` was not installed, and the dump was listed and decrypted. A dump of an upgraded database was restored into a new database on the same cluster, and its row counts, grants and chains matched. A restore on a fresh host, through `age`, into a new object store was not tried. | Try it. |
| the `.env.local` deny list | The loaders (`release/install.sh`, `scripts/launch.sh`, `scripts/_env.py`, `release/install.ps1`, `scripts/launch.ps1`, `scripts/open-ui.ps1` and the one-line loader in `release/INSTALL.md`) leave out names that change how the next program starts: `DOCKER_*`, `COMPOSE_*`, `GIT_*`, `PIP_*`, `NODE_*`, `PSModulePath` and the earlier set. A name outside the list still loads: `HTTPS_PROXY`, `SSL_CERT_FILE` or `REQUESTS_CA_BUNDLE` are read by pip and the other tools the installer starts. Reasoned from the list, not demonstrated. An allow-list would silently stop loading every new setting, which is a quieter failure; the attack needs a handed-over `.env.local` on the victim's machine. | Add a name to every loader's list when a tool is found to read it. |
| a MinIO key is an argument, once | `mc admin user svcacct add --secret-key ...` for the `SAMPLE_` and `PRESERVE_` accounts is visible in the host's process list for the moment it runs, the first time each account is created; its stdout, which echoed the secret into `docker logs minio-init`, is discarded. One bucket each, once, and `hidepid=2` on the Docker host hides it from other local accounts. | `mc` takes the key only as an argument. |
| the application image and the proxy hops | Caddy still runs as uid 0, has a route out, and the hops to Postgres and Redis are plaintext; `./tls` with `private.key` is mounted into every application container. | Terminate TLS in a service of its own; TLS to Postgres and Redis. |
| unpinned inputs | The development compose file's images (`pgvector:pg16`, `redis:7-alpine`), the CI actions, pip and gnupg are pulled by tag, not pinned by digest. | Pin them. |
| a missing hop count | `NOCTORNAL_TRUSTED_PROXY_HOPS` at 0 or unset is neither refused nor reported in production, so the rate limiter meters the whole internet as one subject. | Report it in the register. |
| bucket names have no shell default | `$EVIDENCE_BUCKET`, `$INGEST_BUCKET` and `$SAMPLE_BUCKET` have no default in the `minio-init` script, though the code defaults them. | Default them. |
| the volume name | `release/install.sh` detects a new database volume by the fixed name `noctornal-prod_prod-pgdata`. | Ask Docker. |
| `Server: uvicorn` | The header passes through Caddy to clients. Information only. | Strip it. |
| what was not run | `install.ps1` was never run on a clean Windows machine and nothing was tried on macOS. The installers did not run against a production-shaped Windows host. The production stack was not run behind Let's Encrypt, as a non-root operator, through the secrets and egress upgrade paths, or with a cron job stopped in the middle of a pass. | Run them. |

### Load and performance

Measured on a database of 300 users and 60 cases with one AMBER case of 101,000
entities, 300,000 ties and 1,000,000 claims, at 1, 10 and 50 concurrent users
(release/CHANGELOG.md, Beta 1, has the numbers).

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| the ceiling | Writes, entity and claim reads, selectors, search and audit hold at 100,000 entities and 1,000,000 claims per case, with single-user reads under a second (the register 2.4 s, a report 2.7 s) and no errors at 10 concurrent users. The canvas, the metrics, the report and ego are built for about 5,000 entities per case and past that answer truncated. At 50 users cheap reads reach about 3 seconds at the 95th percentile. | Not proposed. |
| ego and path past 5,000 entities | The ego and path views build only the first 5,000 entities of a case by creation time (`projections.py`) and answer 404 for a centre outside them: 88 of 100 ego requests on the large case. | Build from the centre outward, not from the first 5,000. |
| no statement timeout | Nothing sets a `statement_timeout` on request connections, so an abandoned request keeps running: ten stacked register queries were seen, the oldest ten minutes old. | Set one on request connections. |
| the register grows with the case | The evidence register computes what each exhibit backs for every exhibit on every page (2.4 s at 15,000 exhibits), so a page costs more as the case grows. | Compute it for the page only. |
| a connection for every request | Each request opens a database connection (about 14 ms on the measuring host) and the fixed cost is 45 to 55 ms a request; one process topped out near 75 requests a second, and four workers on Windows reached 101. A pool needs a new dependency. | A pool. |
| measured on one host | Every number is from a Windows host talking to Postgres in WSL2, where a statement costs about 1.2 ms of round trip. The fixed per-request cost and the throughput ceiling are pessimistic for a Linux deployment, which was not measured. The before figures for the graph, projection and report paths are one request each that outlasted the client's timeout, and the betweenness and Leiden analytics were not run on the large case. | Measure a Linux deployment. |

### Tests and code structure

| Id | What is left, and what it costs | What would close it |
|---|---|---|
| duplicated rules | About ten copies of the "is this production" check exist and several hard-code the variable name; about 14 tuples order the TLP levels beside `security/access.Tlp`, and one of them had drifted (the AMBER_STRICT row of the admin list, fixed); `compartments._refuse` duplicates `admin._refuse`. | One `config.is_production()`, one TLP order. |
| test isolation | Some tests skip or fail depending on rows other suites leave (`test_screening_readiness_pg`, `test_review46_screening_window_pg`, `test_telegram_readiness_pg`, the ledger anchor tests), and CI's no-skip gate turns the skips into failures whenever another suite leaves rows; 82 of 99 `client` fixtures repeat the same app and limiter set-up; one module logs under `noctornal.*` and 13 under `noctornal_api.*`; one test sleeps a second four times waiting for lock waits. The roughly 470 test files not sampled were not checked for leftovers. | Roll back in the tests; one `api_client` fixture; one logger namespace; poll `pg_stat_activity`. |

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
support, with vulnerability reports not accepted. quay.io served the last
community builds until 2026-09-25; the CI step and both compose files now
pin the same builds, mirrored byte for byte to this project's GHCR
namespace, for linux/amd64 only: an ARM host cannot pull them.

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

### F32: Key lookups take two people and lapse after 24 hours (F10c, 2026-09-24)

A Web Key Directory lookup is asked for by a Lead investigator or a
Collector and approved and sent by a Lead investigator or a Reviewer who
is not the person who asked. A request lapses after 24 hours (the schema
allows up to 72). Only the hash leaves (no `?l=` parameter, so a directory
that looks keys up by that parameter answers 404), no redirect is followed
and no User-Agent is sent. A key found this way is not confirmed until a
person compares its fingerprint with a published one. **Confirm** the
roles, the lapse and the parameter choice for your deployment.

### F25: Exposure levels other than NONE are the operator's word

Added 2026-09-24 (roadmap F15). A lookup provider's exposure (NONE, VENDOR,
PUBLIC) decides whether a lookup needs a colleague's sign-off and which
labels may leave. The build checks NONE as far as the first hop: its route
must name a private network and a direct send refuses an answer from
outside it. It cannot check VENDOR or PUBLIC at all: the level is what an
administrator wrote, with a basis, and a second administrator approved.

**Confirm the judgement:** that a written basis and two administrators are
enough for a claim the software cannot test, for each provider you
register. docs/16 D9.

### F26: Quota is counted locally and drifts when a key is shared

Each provider's quota is counted from this deployment's own attempt rows,
exactly, in calendar windows. A key also used by another tool, or by a
person in a browser, spends the vendor's quota without this build seeing
it, and the vendor's 429 is then the first sign. The provider cools down
for what the vendor asked, and a refused key locks the provider.

**Confirm the judgement:** that a key registered here is used by nothing
else, or that the quota you enter leaves room for whatever else uses it.

### F29: Eight platforms in the comms catalogue name selector types the ontology does not have

Found 2026-09-24 (roadmap F5.4). `comms.platform.durable_selector_type`
was seeded by 0034 with nine type keys the ontology does not define, in
fourteen rows. TELEGRAM was corrected to TELEGRAM_ID (migration
comms_platform_telegram_type). The other eight are on screen in the Comms
pane and affect display only: normalisation reads
`comms.PLATFORM_SELECTOR_TYPE`, which holds the right keys. Seven map to an
ontology key (TOX_PUBKEY to TOX_PK, JID to JABBER, MXID to MATRIX_MXID,
BRIAR_PUBKEY to BRIAR_LINK, DISCORD_SNOWFLAKE to DISCORD_ID, ICQ_UIN to
ICQ, SKYPE_NAME to SKYPE_ID); WICKR_ID has no ontology type and needs one
first. A follow-up foreign key from the column to `core.selector_type(key)`
would stop a ninth.

**Confirm the judgement:** the seven mappings, and whether Wickr gets a
selector type or its platform row loses its durable type.

### F30: Collected documents are swept only when an operator runs the sweep

Recorded 2026-09-24 (roadmap F5.3); built 2026-10-02.
`scripts/retention_sweep.py` sweeps collected documents past their
retention clock, deployment-wide, by the same purge every other family
uses, so a legal hold on a document, on any version, or on a case citing it
still keeps it. It is dry by default. A real run needs `--apply`, an
authority reference declared in `NOCTORNAL_RETENTION_SWEEP_AUTHORITY`
(recorded on every tombstone and in a `RETENTION_SWEEP` audit event of
counts, refused when missing or a placeholder, never verified, as the L1
policy reference is) and a named active account that holds
`retention.purge`. It is not in the production cron loop, and a test holds
that; infra/production/README.md, Retention sweep, says how to schedule it.
The readiness row `retention_sweep_current` turns red when a document no
hold keeps has been past its clock for more than seven days (docs/00
decisions 171 to 173).

**Confirm the judgement:** that a declared reference and a named account
stand in for step-up on a script that destroys third-party data; that
nobody schedules it until the owner and counsel have said who runs it under
which authority (docs/16 L4); and that the sweep keeps to collected
documents. Dead letters also have no case and no sweep, and are the next
family to decide (F55).

### F55: Dead letters and caseless ingest records are swept by nothing

Found 2026-10-02, while building the F30 sweep; not fixed. A dead letter
carries a 90-day clock and third-party victim data, and is reached only by
`purge_due(case_id=None)`; the case-scoped purge route skips it by design,
and the F30 sweep keeps to collected documents, so nothing destroys a dead
letter when its clock runs out. Ingest records attached to no case are in
the same position. Either family could join `SWEPT_KINDS` once the owner
decides; a dead letter's tombstone already carries no case, so the
cross-case concern decision 172 names does not apply to it. The 2026-10-03
review reported the same gap (evidence-unswept-unattached-and-dead-letter,
low).

**Confirm the judgement:** that dead letters and caseless records may
outlive their clock until that decision, or decide it.

### F38: A logout needs no authority, so the client key opens a few small persona tunnels

Added 2026-09-24 (S2, the egress proxy). A stop (a logout) is always
allowed, for a persona whose authority was revoked or which is burnt as
much as any other, because refusing it would leave a session open on the
platform. So whoever holds the client key can open four stop tunnels an
hour per persona, each at most 256 KiB and 60 seconds, to that persona's
own sites or its profile's networks, with no authority behind them. The
ledger shows each with a Stop chip.

**Confirm the judgement:** that this budget is small enough to leave
unsupervised, against a logout that sometimes cannot happen at all.

### F40: The screening match list counts across compartments

Added 2026-09-24 (roadmap F13). The Security Officer's match list is
label-free on purpose (docs/00 decision 126): an officer must see every
match. The full record opens only within the officer's ceiling, but the
section's status counts include matches in compartments the officer is not
read into, and readiness says only whether matched bytes are waiting,
never how many.

**Confirm the judgement:** that the officer may know how many matches
exist in compartments they cannot open.

### F41: The object stores are reached outside the egress routes

Added 2026-09-24 (S2). The evidence, raw, collected-markup and sample
buckets are reached by their own clients on the internal network, not
through `route_for`, because they are part of the deployment rather than
outside it. An object store on another host (an off-host `MINIO_ENDPOINT`)
therefore has no route: in the production topology the application network
cannot reach it at all.

**Confirm the judgement:** that the object store stays on the deployment's
own network, or decide how an off-host store is reached and recorded.

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
with a defective build can be found later. Since 2026-09-24 (F10a) a build
below the floor counts as no verifier, gpg never starts an agent
(`--no-autostart`), and every key and detached signature is walked for
OpenPGP framing before gpg sees it, which refuses secret key material outright.

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

The Analysis pane's forum and wallet projection (2026-09-24,
`affiliation.py`) follows both rules, with one caveat worth flagging: a
case records only its own posters and controllers, so a venue's size in the
case graph is a lower bound (raised by an analyst-recorded member count
where one exists), and every Newman weight drawn from it is an upper bound.
Every payload says so. Sizes are taken from every membership the caller can
see before any filter, so the accepted-ties scope or a confidence floor
never shrinks a venue under its cap.

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

### F27: No lookup adapter has been verified against its live service

Added 2026-09-24 (roadmap F15). The VirusTotal v3, Shodan host and MISP
restSearch adapters were written from vendor documentation and tested
against recorded answers only. Each says `live_verified` false, and the
Providers card and the readiness row say so. A vendor answer the adapter
cannot read becomes an UNREADABLE answer with the raw bytes kept, never a
guess. **The cost:** the first live use may find a field that moved.

**A second cost, of the personal-data refusal:** a JABBER address is shaped
like an email address and cannot be told apart from one, so JABBER
selectors are refused with personal data toward every provider.

### F31: The Telegram adapter has never met Telegram

Recorded 2026-09-24 (roadmap F5.2 and F5.3). Every Telegram test runs
against a fake transport, and the SOCKS5 path through Telethon is tested
against the egress contract's stub proxy on loopback, whose dial to a data
centre the test refuses. Enrolment, a poll, a join and a logout have not
been run against Telegram through the real egress proxy, and a test now
runs a persona's run, act and stop contexts through the real listener
(`test_persona_contexts_through_proxy_pg.py`). `scripts/telegram_live_check.py`
is the owner's one run against a real Telegram account, which only the owner
can make, and F31 stays open until it is run. Telethon 1.x is maintained by one
author, and pyaes, which it uses for AES-IGE, has had no release since
2017: a flaw in either lands on the host that holds every persona's
session. The DC network list is Telegram's published one of 2026-09-24,
and a new range fails closed until it is updated.

### F44: A retention rule confirmed later does not reach documents collected before it

Added 2026-09-24. A collected document's clock is set when it is stored,
from the category rule in force then. No FORUM_POST or FORUM_MEMBER rule is
seeded, so forum documents collected before an operator confirms one stay
unclocked, and a rule confirmed later reaches only what is collected after
it. Readiness says so while no forum rule exists. Setting clocks on
documents already held is a destruction decision, and is not made by a
migration.

### F45: There is no source-wide legal hold

Added 2026-09-24. A hold is placed on a document, with every earlier
version, or on a case, which holds every document it cites. Nothing holds
everything a source has collected in one act. Since Beta 1 a case can be held
through the API (`POST /api/v1/retention/cases/{id}/legal-hold`), and a hold on
a case holds every document it cites; the console has no control for
it (Known residuals at Beta 1).

### F46: A raw markup object can be left unreferenced

Added 2026-09-24. Raw markup is written to its bucket before the document
row that names it. When storing the row fails and the compensating delete
of the object fails too, the object stays in the bucket with nothing
naming it, outside every retention clock and hold.

**The cost:** rare, and found only by listing the bucket against
`collect.document`.

### F48: One post read by a board source and a thread source is stored twice

Added 2026-09-25 (roadmap F3, F4). Deduplication is per source, so the same
post collected through a board and through a thread of that board is two
documents. The per-forum lock keeps the request rate right; the analyst sees
the post twice.

### F49: What the forum parsers do not read

Added 2026-09-25 (roadmap F3, F4). An empty MyBB board is recognised only by
its English "no threads in this forum" text, so an empty board in another
language reads as parser drift. XenForo reactions give only the names the
reaction bar shows, and its "and N others" count is read in English only.
MyBB reactions are not parsed. Many boards require sign-in for member
profiles, and those pages are skipped with a warning. An ambiguous MyBB time
inside a daylight-saving change is taken as its first occurrence.

### F50: That a claim is not in a similarity index stays visible

Added 2026-09-25 (roadmap F6). A claim's similarity reason is told only as
its reader may know it: the stored reason when the reader can read
everything the claim cites, and otherwise what their own readable facts
give, or that it cannot be compared. Whether a claim is in an index at all
is still visible, because the claim gate includes the material it cites.

### F53: No route or console form creates a watch

Added 2026-10-02 (F47). Only `scripts/seed_feeds_demo.py` inserts a watch,
so a watch of target kind TELEGRAM_CHAT can today be written only by hand,
and its reference rule (a typed chat id) is held by the database (Alembic
0130) and the matcher rather than by a creation route.

### F54: A TELEGRAM_CHAT watch with no term fires on every message

Added 2026-10-02 (F47). A chat watch with no keyword, selector or pattern
matches every message of its chat, as the schema's "capture everything"
says, thinned only by its suppression window (3600 seconds per chat or
topic by default; 0 is one hit per message). A term in a forum signature
raises a hit on every post of that author, because the signature repeats
on each.

---

## Deferred security items

Not defects, not done. Listed so they are not mistaken for oversights.

| Item | Consequence today |
|---|---|
| Session binding by default | Every session records the address and client it was minted from (0058), and `NOCTORNAL_SESSION_STRICT_BINDING=1` refuses a mismatch with an audit row. A production start refuses to run without it, and `infra/production/secrets.env.example` sets it. In development it is off by default, so a stolen token is portable there |
| WebAuthn | TOTP only. A deliberate absence, stated in four documents; SECURITY.md says reporting it is not a finding |

Row-level security is no longer on this list: it stands on 82 tables and
defers none (F51, in the table below). What the request role can still reach
outside it is under Known residuals at Beta 1.

---

## Closed

Kept as an index, because the value of this register is that a reader can tell
a judgement nobody has confirmed from one that somebody has. The reasoning
behind each closure is in `release/CHANGELOG.md` under its date.

| | What it was | Closed |
|---|---|---|
| **The 2026-10-03 review** | 82 findings, 16 high, 25 medium and 41 low (section above) | 2026-10-07: 77 fixed, one fixed for credentials and stated for the rest (rls-6), four stated and not fixed. Each one's status is in The 2026-10-03 review at Beta 1, and what the fixes left is in Known residuals at Beta 1 |
| **F51** | Five tables were not under row-level security: the audit log, and the ingest records, victim credentials, dead letters and PII authorisations | 2026-10-03: all five are under policy and no table is deferred, 82 under policy (Alembic 0152 to 0155 and 0166 to 0169, docs/00 decisions 76, 143 and 151). `rls_registry.DEFERRED` is empty and a registry test names any table that carries labels and is in none of the three lists. Row security stays enabled and never forced (decision 143) |
| **F52** | The schema owner's password still reached the runtime services | 2026-10-02 to 2026-10-03: `POSTGRES_PASSWORD` and `NOCTORNAL_MIGRATION_DATABASE_URL` moved into `postgres-init.env` and `migrate.env`, each read by one service, and the API and every cron job refuse to run holding either; the rate limiter's Redis runs under an ACL and the limiter signs in as `noctornal_limiter`; every job script makes one refusal on a published credential (`release/secrets-upgrade/README.md`) |
| **F42** | Parse and analysis children were bounded, not isolated, so a parser exploit in a hostile sample or page was a compromise of the deployment | 2026-10-03: in production each hostile read (static triage, archive expansion, watch patterns, forum pages) runs in `analysis-worker`, a container with no secrets and no network, reached over a Unix socket (`infra/production/README.md`, Analysis worker). A local child remains for development, and `NOCTORNAL_ANALYSIS_LOCAL=1` keeps it in production on purpose, which the register reports |
| **F43** | Collected documents carried no compartments unless captured, so compartmented work was collected by hand | 2026-10-03: `collect.source` can carry compartments (Alembic 0163, 0164), every document a source collects carries them, and the readers, the notices, the Telegram path and the capture path honour them (docs/00 decision 78) |
| **F28** | A webhook signature carried no timestamp and no replay window | 2026-10-02: an opt-in signature v2 signs a timestamp with the body (`NOCTORNAL_WEBHOOK_SIGNATURE=v2`); docs/07 gives the receiver's replay window, the order to move in and a verifier (docs/00 decision 167). A receiver still on v1 stays replayable as before, which is the cost for anyone who does not opt in |
| **F35** | A persona could be created on a profile that cannot carry persona traffic | 2026-10-02: refused at creation, in the egress proxy's own sentence (`test_persona_creation_exit_pg.py`, decision 164) |
| **F36** | A run's warning lost a typed Telegram id | 2026-10-02: the ids this product's adapters write (`c:`, `g:`, `post:`, `member:`) are kept in a run's item label, and every other id still passes the redactor (`test_item_label_typed_ids.py`, decision 165) |
| **F37** | gpg's own fingerprint display did not parse in a contact block | 2026-10-02: whole hex groups are kept on `PGP_FPR` lines and the parser version is cb-2 (decision 166). Blocks parsed under cb-1 keep their reading and are in the untrusted-data table above |
| **F39** | The second person on a case's merge switch had no seasoning rule | 2026-10-02: the owner settled it. The second person must have held `case.update` on the case for a window the deployment sets (`NOCTORNAL_RELAX_SEASONING_DAYS`, 7 by default, 0 off), checked when they approve and again where the approval is spent (docs/00 decision 169). Still open inside it: an administrator who resets a seasoned colleague's credentials and signs in as them is not covered |
| **F47** | Watches matched neither forum signatures nor Telegram chats | 2026-10-02: a post's signature is matched with reasons of its own, and a watch can target a Telegram chat by its typed id, which Alembic 0130 holds (decision 168). No route creates a watch yet (F53), and a chat watch with no term fires on every message (F54) |
| **F33** | The production compose file did not run the similarity pass, although readiness said to start one | 2026-09-25: an `embed-pass` service runs it in a loop of its own |
| **F34** | The production image carried no gpg, so every PGP check recorded NO_VERIFIER | 2026-09-25: the image installs the distribution's gnupg; a deployment attests it with `NOCTORNAL_GPG_PATCHED_AS` after checking its changelog, as CI does |
| **SSRF through an egress proxy** | Persona traffic had no egress proxy, and a forward proxy resolves a name again, so the collector could not simply consult one | 2026-09-24: the egress proxy is built and is the only way out of production (docs/00 decision 68, docs/20). It resolves each name once and dials only the admitted answers, with the same `egress_policy` functions the pinned client applies in development, and a chained exit receives the name, never an address this platform resolved |
| **SSRF rebinding** | `collection.fetch()` checked one DNS answer and connected with another, so a name answering public and then internal reached the internal address | 2026-09-23: each hop's name is resolved once and the socket goes to the address that was checked, while `Host`, TLS SNI and the certificate check stay on the name. `test_collection_ssrf_rebinding.py` proves it against a resolver that answers public, then internal |
| **F2** | `REJECTED` samples were destroyed by default | 2026-09-22, decided by the owner: preserved under a legal hold in their own object-locked store, two people to retrieve, destroyed only by declaration and never under a hold (section above) |
| **F14** | Which roles may invoke break-glass was a guess | 2026-09-22, decided by the owner: invoke with CASE_OWNER and SYS_ADMIN, review with SECURITY_OFFICER only; migration 0062 keeps the two apart |
| **F16** | `victim_pii.reveal` was granted to no role | 2026-09-22, decided by the owner, migration 0062: the Lead investigator reveals, the Security Officer alone authorises |
| **F24** | The evidence store's upstream is archived | 2026-09-22, decided by the owner: stay on the pinned build, risk accepted in writing, and the register now proves write-once instead of reading it (section above) |
| Compartment rename and removal | The registry bound every compartment column (0059) and refused to drop or rename a key any row carried, with no product route to do either, so a mistyped key was a hand-written UPDATE on eighteen columns | 2026-09-23: `POST /api/v1/compartments/{key}/rename` moves a key everywhere in one transaction without changing who holds it, and `/retire` drops a key nothing carries and otherwise counts what does, naming only the accounts, cases and ingest keys the administrator can already see (`user.manage`, step-up, audited; Admin, Compartments). `test_compartment_lifecycle_pg.py` holds both |
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
