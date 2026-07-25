# 00 — Decisions and open questions

## Decisions taken in this scaffold

| # | Decision | Because | Cost if reversed later |
|---|---|---|---|
| 1 | Identity and Person are separate node types | Attribution is an assessment, not an observation | High — every edge repoints |
| 2 | Assertion layer under all graph elements | Retraction, provenance, "what did we know when" | Very high — full rewrite |
| 3 | Postgres as system of record, graph DB optional downstream | Data is relational; analytics want memory-resident anyway | Low — projection layer absorbs it |
| 4 | Bitemporal from day one | Temporal replay and disclosure both need it | Very high |
| 5 | Signed edges | Trust networks are meaningless without negative ties | Medium |
| 6 | Ontology in tables, not enums | Types will change monthly in the first year | Low |
| 7 | Machines propose, humans dispose | Auto-ingested graphs are landfill | Medium |
| 8 | Zanzibar-style authz (OpenFGA/SpiceDB) | Access is relationship-shaped | Medium |
| 9 | Collectors in an isolated zone, no DB access | Contains a burnt-persona compromise | Medium |
| 10 | Single-tenant | Multi-tenancy on this data class is a liability | High |
| 11 | igraph over NetworkX | NetworkX dies around 50k edges | Low |
| 12 | Legal basis and retention `NOT NULL` | Optional governance fields end up empty | Low |
| 13 | Prosecution-grade evidence, US + Canada (2026-07-24) | Data may support prosecution; WORM store, custody ledger and hash verification are load-bearing Phase 1. Authenticity targets: US FRE 901/902(13)–(14) (records of a regular electronic process, hash-value certification); Canada Evidence Act ss. 31.1–31.8 (integrity of the electronic documents system). The canonical, replayable audit hash chain exists for this | Very high — cannot be retrofitted onto evidence already collected |
| 14 | Renamed `lattice` → NocTORnal pre-Phase-0 (2026-07-24) | Folder/product name was decided; the identifier lands in the DB, buckets, key prefix (`noct_sk_`), compose project | N/A — done before anything referenced it |
| 15 | Collapsed duplicate `TOX_ID` selector into `TOX_ID_FULL` (2026-07-24) | Two keys for the same 76-hex observable fragment cross-case pivoting; `TOX_PK` remains the only strong Tox selector (invariant 9) | Low now, high after data lands under both keys |
| 16 | Operating context: law enforcement primary, private CTI secondary (2026-07-24) | Legal-basis vocabulary and disclosure features target LE first (Canada: judicial authorisations/production orders, Stinchcombe disclosure; US: warrants/2703(d), Brady); collection defaults stay conservative. Private-CTI deployments relax configuration, never schema | Medium — vocabulary and export templates rework |
| 17 | Alembic owns the schema; `db/schema.sql` + `db/seed_ontology.sql` are mirrored reference (2026-07-24) | One authoritative change path (`db/migrations/`, one concern per revision, all reversible) while keeping a readable end-to-end DDL; initdb loads extensions only (superuser) | Low — squash migrations, regenerate reference |
| 18 | Telegram evidence CAPTURE in MVP; automated monitoring adapter deferred (2026-07-24) | Telegram is where current-market crime happens, so analysts must be able to file Telegram captures as first-class evidence (manual/assisted export upload with full custody). The high-risk part — persona-driven automated monitoring (MTProto, FLOOD_WAIT, overt joins) — stays deferred; monitoring can be handwork for now. RSS + XenForo still prove the pipeline | Medium — capture-format parsing is reusable by a later adapter, so little is thrown away |
| 20 | Selector hardening pass, Alembic 0018 (2026-07-24) | Adversarial review found wrong-merge/missed-merge normalisers: Telegram IDs now keep chat/user namespaces, JIDs drop the resourcepart, Session IDs case-fold as hex, MXID localparts stay case-sensitive (spec), TLSH loses the T1 prefix, onions/IBANs/asdot-ASNs/phone extensions canonicalise, IDNA2008 replaces stdlib IDNA2003 (faß.de ≠ fass.de). `FORUM_UID` (unscoped, per-venue), `PDB_PATH` and `CODESIGN_CN` (attacker-controlled text) demoted from is_strong — FORUM_UID may return to strong once the norm form is venue-scoped | Low now; every deferred day of a wrong-merge normaliser poisons selectors |
| 41 | Entity merge is a LEDGER, not a flag, and never crosses the persona/person boundary (2026-07-25, Alembic 0027, apps/api merges.py) | docs/01 opens its entity-resolution section with "merging is the operation most likely to quietly corrupt a case" and requires that "its edges are re-pointed with a record of the original endpoints". `core.node.merged_into_id` had existed since 0005 with nothing writing it, because a merge is not one column: re-pointing destroys the original fact, so `core.node_merge` + `node_merge_edge` record every moved endpoint and reversal is a RESTORE rather than a re-derivation -- working out where an edge "should" go after the fact is the same guesswork that made the merge wrong. A tie BETWEEN the merged pair would become a self-loop, which core.edge forbids, so it is recorded and soft-deleted and comes back on reversal. A partial unique index allows re-merging after a reversal while forbidding two live merges of one node. Reversed merges stay in the history, because a merge that vanished would hide that somebody once believed these were the same actor. IDENTITY may never merge into PERSON: that is an ATTRIBUTION carrying a confidence (invariant 2), and a merge asserts the records ALWAYS described one thing. Step-up gated per docs/01, via a new composable `require_step_up` dependency; the case-owner notification docs/01 also asks for is Phase 5 and is NOT built | High if the ledger is dropped later -- the reversal data has nowhere else to live |
| 40 | Manual capture before adapters, and it is the FIRST producer of proposals (2026-07-25, apps/api extraction.py) | docs/14 C2 recommends exactly this: "a paste-a-conversation-export path that lands a document, extracts selectors with offsets, and proposes graph changes would exercise the whole proposal pipeline without any of the persona-management risk". Phase 4's adapters are a large build with real operational hazard (personas, egress binding, FLOOD_WAIT, parser drift) and none of it is needed to prove the part that matters. Text lands as a `collect.document` deduped on content hash; regexes produce `collect.extraction` rows WITH character offsets; each new value becomes a proposal carrying the matched span and its surrounding sentence, because a handle lifted out of a quoted signature block looks identical to a real one until you see the context. Deliberately proposes SELECTOR nodes only -- never PERSON, because attribution is an assessment a human makes (invariant 2). The document is deduped GLOBALLY but proposals are per-case: the same thread pasted into a second case must still raise proposals there. Scores state how often the PATTERN is wrong in prose, not how important the finding is | Low - the extractor is replaceable; the pipeline it feeds is the durable part |
| 39 | Proposal pipeline: invariant 3 enforced by CLASS SHAPE, not by discipline (2026-07-25, apps/api proposals.py) | `collect.proposal` had existed since Phase 0 with nothing writing it, so "machines propose, analysts dispose" was true by accident rather than construction -- the only one of the three founding ideas with no enforcement. Split in two: `ProposalStore` is the extractor-facing half and holds NO GraphWriteService, so it is physically unable to reach `core.node`/`core.edge`; `ProposalReview` is the only path into the graph and requires a human `reviewed_by`. Accepting applies through GraphWriteService, so the element and its assertion commit together (invariant 1) -- an accepted proposal is an analyst making a claim, not a back door. The assertion is basis AUTOMATED_INFERENCE at LOW confidence carrying the extractor's name and rationale, and an accepted EDGE is born `is_inferred` (invariant 4), so accepting a suggestion cannot silently move anyone's centrality. A DISPUTED state exists because a queue whose only options are yes and no forces a decision on ambiguous items, which is how junk gets accepted. No HTTP endpoint CREATES a proposal: they come from extractors inside the boundary | Medium - the review semantics are load-bearing for Phase 4 |
| 38 | One destination-aware egress gate, and evidence now goes through it (2026-07-25, apps/api egress.py) | docs/07 opens by requiring "one function, `can_egress(object, destination)`, called by SMTP, Jira, webhooks and export alike", because integrations are the leak path in every system of this kind -- a Jira ticket auto-created from a watch hit quietly copies intelligence into a system with a different access model and a wider audience. Evidence carried its OWN frozenset of non-egressable classifications; a second copy is how copies drift, and the one that drifts is the leak. The gate is pure (labels in, decision out) so it is exhaustively testable, and it fails CLOSED on an unknown classification, an unknown destination or an unparseable ceiling. A per-destination ceiling can only ever LOWER what is permitted -- the AMBER_STRICT/RED floor is checked first so no integration config can argue past it. Compartmented material never egresses at all: no external system models compartments, so sending it would silently drop the control rather than enforce it elsewhere. The message keeps the literal phrase "invariant 8" because tests assert on it | Low - additive, and it removed a duplicate rather than adding one |
| 37 | Layout: hand-written ForceAtlas2 + Barnes-Hut in a Web Worker, NOT sigma.js/graphology (2026-07-25, static/layout-worker.js) | docs/02 asks for "ForceAtlas2 with Barnes-Hut in a worker" and docs/14 U1 records the blocker: the UI ships under `script-src 'self'` with no bundler and no inline script, so an npm dependency means adopting a build step. That is a real decision and should not arrive as a side effect of wanting a layout. A worker is a same-origin script file, so it needs neither. Barnes-Hut takes repulsion from O(n^2) to O(n log n); measured 400 nodes / 1,187 edges in ~1s off-thread, and cluster separation improves 1.1x -> 9.3x by 400 iterations on planted-cluster fixtures. The main-thread spring loop is KEPT for interactive drag, which wants immediate local response. Progress posts are rate-limited to ~10/s and repaints coalesced onto animation frames | Low - swapping in sigma.js later is a renderer change, and the bundler decision stays open |
| 36 | NO prohibited-content policy exists, and Phase 8 (sample handling) MUST NOT ingest until one does (2026-07-25) | docs/09 Phase 8 says "Decide first: the prohibited-content policy, with counsel, before the first ingest rather than after." It has not been decided and is not something this build can decide for itself: a malware/sample store that accepts arbitrary attacker-supplied binaries will eventually receive material whose mere possession is an offence, and the handling obligations differ by jurisdiction (the deployment targets Canada AND the US, decision 13). Recorded in the README as an explicit blocker rather than left implicit in a roadmap footnote. Phases 0-7 are unaffected -- none of them stores a sample | Very high if ignored - the cost of discovering this after the first ingest is legal, not technical |
| 35 | Phase 7 comms: MESSAGE-LEVEL capture, not metadata-only (2026-07-25, operator decision) | docs/09 asked the question and noted metadata is "dramatically cheaper and carries most of the analytic value". The operator chose message-level anyway, which is the defensible call for a law-enforcement-primary deployment (decision 16): message CONTENT is what a disclosure obligation and a prosecution actually turn on, and a metadata-only capture cannot be re-run against a channel that has since been deleted. The costs are accepted and real: storage grows with traffic rather than with the number of parties, every captured message is personal data inside the retention and minimisation regime, and the TLP egress gate (Phase 5) becomes load-bearing rather than advisory | High - re-capturing content that was only ever seen as metadata is usually impossible |
| 34 | Retraction is enforced in the projection AND exposed in the UI; provenance strength is drawn on the canvas (2026-07-25, enhancements E1-E3) | The first real session produced 14 assertions and ZERO exhibits, and retraction -- the operation that makes the assertion model load-bearing -- was reachable from no interface at all. Now: an assertion can carry its exhibit at the moment the claim is made (`evidence_id` had existed unused since Phase 1), the projection reports `has_evidence` per element, unevidenced entities render with a hollow core and unevidenced ties render faded, and case-level evidence coverage is a headline number that reads red at zero. Retracting the last live assertion visibly dissolves the element from the live graph. An exhibit may only support a claim in its OWN case | Low - additive |
| 33 | Two-mode projections are WARNED about, never silently rewritten (2026-07-25) | docs/03 says CONTROLS "will wreck centrality if included", yet the Financial preset includes CONTROLS/TX_INPUT/TX_OUTPUT (making WALLET and TRANSACTION vertices) and Communication includes PARTICIPANT_IN (making CONVERSATION one). Centrality over that answers a different question: an artefact with several controllers scores as a broker. Editing PRESETS would silently change every number the Phase 2 sociogram already shows, so the analytics response carries a `mode_warning` naming the non-actor types instead, distinguishing ones that carry ties (distort brokerage) from isolates (only inflate the percentile denominator). Proper bipartite projection to one-mode with Newman weighting is still open | Low - the warning is additive; a real one-mode projection is a new parameter |
| 32 | Live-assertion filter implemented in `GraphService.project()`, completing decision 24 (2026-07-25) | Decision 24 scoped LIVE provenance as "a PROJECTION property, NOT write-enforced" so a retracted element could dissolve from the live graph while its rows survive for temporal replay. The projection never implemented it, so retraction was cosmetic: the UI showed a RETRACTED chip while the node kept its full degree, and Phase 3 would have computed betweenness and takedown targets over withdrawn evidence. Both SELECTs in `project()` now require `EXISTS (... assertion WHERE retracted_at IS NULL)`. Zero assertions were retracted when this landed, so no existing number moved | Low now; the cost was in leaving it undone |
| 31 | A metric run is cached against the CALLER'S VISIBILITY, not just the graph (2026-07-25, Alembic 0026) | `project()` filters by the caller's clearance and compartments, so the same question over the same case yields different graphs per analyst. A cached betweenness computed over RED nodes served to an AMBER analyst would hand them a score whose entire explanation is a node they may not see. Two independent mechanisms: `graph_hash` is taken over the caller-VISIBLE node and edge lists, AND the lookup filters on `visibility_clearance` / `visibility_compartments`. Both columns are NOT NULL with NO DEFAULT deliberately - `'{}'` is what an analyst holding no compartments looks up with, so a default would make a forgotten write fail OPEN. Cost: two clearances that happen to see an identical graph each compute their own run | Low - stricter than needed, and the strictness is the point |
| 30 | Phase 3 analytics run SYNCHRONOUSLY in the API process, not in a separate worker (2026-07-25, apps/api analytics.py + analytics_runs.py) | docs/02 puts "analytics workers (igraph)" in Zone B, but a queue adds a process, a client dependency, a progress-reporting UI and a new failure mode without changing a single number at the scale this tool has. docs/03's own band is "< 5k nodes: exact, everything, synchronous, sub-second", and measured: 2,000 nodes / 6,000 edges is 1.15 s for the whole suite. The compute layer is nevertheless written worker-ready - `analytics.py` is pure and database-free, `analytics_runs.py` owns all persistence, so moving to Arq/NATS is a change of caller, not of algorithm. Caps enforce the band: betweenness switches to Brandes pivot sampling above 3,000 nodes, key player refuses above 5,000 or on a truncated projection. ACCEPTED CAVEAT: this is a CPU-bound path behind a non-step-up permission with rate limiting still deferred (decision 29), so it is a DoS surface for an authenticated, case-assigned analyst | Medium - the seam is deliberate, but a worker still needs a queue, a runtime and progress UI |
| 29 | HTTP API layer, hardened after adversarial review (2026-07-25, apps/api/http/) | FastAPI under `/api/v1`, problem+json, security headers; every case-scoped endpoint depends on `require()`/`authorize_object` so authorization is decided once. Review found and fixed: **effective labels** (an element is protected by the STRICTER classification and the UNION of compartments with its case — uploaded evidence has empty compartments, so the need-to-know leg was passing vacuously); **the case listing** now applies verb+lattice+compartments in SQL (it applied none of them); **search** filters by the CALLER's ceiling, so an over-classified label/title is invisible rather than discoverable-then-403; **write ceiling** (you cannot author content above your clearance); **no raw psycopg text or submitted input** in responses (a 422 was echoing the submitted password and live TOTP code); **CSRF** double-submit for cookie-authenticated unsafe methods; **logout revokes one session**, not all; **lockout decays** (it never did — one bad login every 15 min locked an analyst out forever); **auth/authz events audited**; existence oracles closed (no-relationship ⇒ 404, same as nonexistent). DEFERRED and documented in apps/api/README.md: rate limiting, session IP/UA binding, login timing equalisation, compartment registry | Medium — endpoint wiring is where authz regressions hide, hence the e2e suite |
| 28 | Tags, node sets, full-text search (2026-07-24, Alembic 0025, apps/api curation.py) | Tags = controlled vocab (namespace+name), case-scoped or global (case_id NULL), hierarchical (parent_id), external_id for MITRE; unique per (case,namespace,name) or global. Node sets = ad-hoc analyst working sets, deliberately NOT edges (so they never distort centrality, docs/01). Search over the trigger-maintained tsvectors: nodes (label+attrs, excludes soft-deleted/merged) and evidence. Migration 0025 added the MISSING evidence search_tsv trigger (title+description+extracted_text, 500k-capped) — evidence had the column + GIN index (0008) but nothing populated it, so evidence search silently returned nothing until now | Low |
| 27 | Case CRUD service (2026-07-24, apps/api cases.py) | Creating a case atomically grants its owner (and deputy) CASE_OWNER access — the five-part gate reads roles off case_assignment, so without this the owner couldn't act on their own case. Validated status lifecycle (DRAFT→ACTIVE→DORMANT↔ACTIVE→CLOSED→ARCHIVED→PURGED; illegal transitions rejected; closed_at stamped). Governance guards beyond the schema: lawful basis non-empty, review_due≤retention_until, and owner/deputy clearance ≥ case classification (a sub-cleared owner could never see their own case — caught at creation). Every create/edit/status/grant/revoke writes a hash-chained audit.event. Owner access cannot be revoked | Low |
| 26 | Evidence: WORM storage + dual-hash + tamper-evident custody (2026-07-24, Alembic 0023-0024, apps/api evidence.py) | Prosecution-grade (decision 13), hardened after an adversarial review. Bytes → MinIO object-lock in **COMPLIANCE** mode (not GOVERNANCE — not even root can delete/overwrite before retention; true WORM). SHA-256 **and** BLAKE3 computed from original bytes at ingest; read-back verified after PUT; **every read (view/export) recomputes and fails closed** on mismatch, so a swapped object version cannot be served with a clean log. Custody ledger is append-only (0023) AND hash-chained with server-pinned occurred_at + actor FK (0024) — back-dating/forged-actor/deletion all detectable. Every touch also writes a hash-chained audit.event; linking is audited (EVIDENCE_LINKED); dedup still records custody. export() enforces the invariant-8 floor (AMBER_STRICT/RED never leave the boundary). DEFERRED: full destination-aware egress gate (Phase 5); API should run as a non-owner DB/MinIO role in production (privilege separation) — the hash chain is the detection backstop until then; object-versionId pinning is a further hardening | High — chain of custody cannot be reconstructed after the fact |
| 25 | Selector storage wired to the ontology normalisers (2026-07-24, apps/api selectors.py) | core.selector is the entity-resolution join key; every write runs raw→norm through noctornal_ontology.normalise (the ONE source), so the DB norm_value cannot drift from the ontology. UNIQUE(case,type,norm) ⇒ a selector is one row/owner per case, so "same observable, two owners" is only expressible CROSS-case; a within-case merge lead is instead an attribution conflict at link time (strong selector already owned ⇒ SelectorOwnerConflict, force to repoint). node_id is observation bookkeeping, not an asserted edge (assert ownership via a CONTROLS edge). Cross-case pivot requires the caller's allowed_case_ids, so it cannot leak past open question 5. No schema change (table exists since 0005) | Low |
| 24 | Assertion layer enforced in the database, steady-state (2026-07-24, Alembic 0022) | Invariant 1 is a SYMMETRIC pair of DEFERRABLE INITIALLY DEFERRED constraint triggers: (1) AFTER INSERT on node/edge — no element commits without an assertion row; (2) AFTER DELETE OR UPDATE OF node_id/edge_id on assertion — the LAST assertion of a still-existing element cannot be deleted/repointed. Trigger 2 closes the two paths trigger 1 alone missed (SET CONSTRAINTS ALL IMMEDIATE timing game; later-transaction delete) — an adversarial review found both. The guarantee is thus ">=1 assertion ROW per element at ALL times", via any write path. GraphWriteService is the atomic API on top. SCOPE (deliberate): LIVE provenance (>=1 non-retracted assertion) is a PROJECTION property, NOT write-enforced, because retraction propagation (docs/01) requires an element to lose all live support and dissolve from the live graph while its row + history persist for temporal replay. Per-attribute provenance (claim_path) is supported but is application discipline | Cannot be retrofitted — the one GETTING-STARTED says never skip |
| 23 | Role→permission matrix seeded (2026-07-24, Alembic 0021) | Roles and permissions existed but were unlinked, so the verb check had nothing to read. Starting matrix (58 grants): SYS_ADMIN/SECURITY_OFFICER hold NO case-content permissions (separation of duties); CASE_OWNER full incl. grants + dual-controlled destructive verbs; ANALYST creates/edits but no grant/review/export; REVIEWER approves not originates; CONTRIBUTOR uploads not accepts; READ_ONLY/LIAISON view only. Change via role.manage + migration | Low — data, re-seedable |
| 22 | Orphan node types wired in; TRANSACTION = proven criminal on-chain tx (2026-07-24, Alembic 0019) | TRANSACTION gains TX_INPUT/TX_OUTPUT wallet legs (two-mode money graph; PAID stays the actor summary); DATASET/CREDENTIAL_SET gain CONTROLS (held-by) and EXFILTRATED_FROM (breach provenance to victim). All structural. Resolves open question B. 49 edge types now | Low — new edges, no rework of existing data |
| 21 | Structural edges out of the social projection; SAME_AS layer-gated (2026-07-24) | `PARTICIPANT_IN`, `SAME_DEVICE_AS`, `CO_POSTED_IN`, `SHARED_INFRA` are bipartite/plumbing edges — counting them social double-counts affiliation or fabricates alliances (two rivals on one bulletproof host are not friends). The edge validator now rejects SAME_AS crossing the IDENTITY/PERSON layer: attribution is exclusively ATTRIBUTED_TO (invariant 2) | Medium — projections built on the old flags would need recomputing |
| 19 | Stealer logs in scope but SEGREGATED — never inside the core evidence store (2026-07-24) | Stealer logs are bulk third-party PII, the most likely route to a data-protection incident. They upload to a samples-style segregated environment (separate origin/bucket/compartment, docs/11 model): metadata and extracted selectors may flow to the graph as assertions; raw dumps never enter `core.evidence`. PII masking and minimisation land before any stealer ingest code | High — once raw dumps sit in the case store, retention/disclosure obligations attach and cannot be unwound |

---

## New open questions raised in session 2 (ontology)

**B. RESOLVED 2026-07-24 (decision 22).** TRANSACTION, DATASET and
CREDENTIAL_SET are wired into the edge vocabulary (Alembic 0019).
TRANSACTION is a *proven criminal on-chain transaction*: wallets are its
inputs (`TX_INPUT`) and outputs (`TX_OUTPUT`), so the money graph stays
two-mode and identities reach it through `CONTROLS`→wallet; `PAID`
remains the actor-level summary edge and the two coexist. DATASET and
CREDENTIAL_SET can be held by an actor (`CONTROLS`) and carry breach
provenance to a victim (`EXFILTRATED_FROM`). All three new edges are
structural (not social ties).

**D. Two-step MFA UX needs an opaque ticket.** Session-3 auth is
deliberately single-step: the client submits password AND TOTP together
and gets one generic INVALID_CREDENTIALS for any wrong factor. A
"password first, then prompt for code" UX would leak password validity
(a free, lockout-free password oracle) unless the transition is gated by
a short-lived opaque MFA ticket issued indistinguishably whether or not
the password was correct (identical response, identical Argon2 work, a
lockout increment either way). Build that ticket flow before offering a
two-step login. Found by the session-3 adversarial review.

**A. Venue-scoped FORUM_UID.** A forum UID is unique per forum, not
globally; unscoped it is a wrong-merge factory, so it is currently weak.
To restore auto-merge we need the ingest layer to produce a venue-scoped
norm form (e.g. `<forum-slug>:42`), which means selector matching gains a
venue dimension. Decide when the collection layer is designed.

**B. TRANSACTION / CREDENTIAL_SET / DATASET are orphan node types.** They
are decided node types but appear in no edge type's endpoints, so a node
of one of these kinds cannot currently be connected to anything. Decide
which edges they belong on (e.g. TRANSACTION alongside PAID, DATASET/
CREDENTIAL_SET as objects of SOLD_TO / CONTROLS) before graph-authoring
UI lands — deferred to keep this pass to verified fixes only.

**C. IDENTITY-target BANNED_BY in the signed projection.** A moderator
banning a user is a negative trust signal (docs/01), but BANNED_BY also
targets venues (FORUM/CHANNEL) which are not. The single is_social_tie
flag cannot split by endpoint; resolving this needs the endpoint-aware
projection rule planned for Phase 2 analytics.

## Open questions — worth answering before Phase 1

These are the places I made a call without enough information. Each one is
cheap to change now and expensive later.

**1. Jurisdiction and operating context.**
Are you law enforcement, a private CTI vendor, a CERT, or in-house
security? This changes the legal basis vocabulary, the retention defaults,
whether disclosure packs matter at all, and how conservative the collection
defaults should be. I have defaulted to something that would satisfy a
European LE or a regulated private vendor, which is the strictest common
case — easy to relax, hard to tighten.

> **Answered 2026-07-24:** jurisdiction is **Canada + US**; operating
> context is **law enforcement primary, private CTI secondary**
> (decision 16). Legal-basis vocabulary and disclosure features target
> LE; collection defaults stay conservative.

**2. Will this data ever go to a prosecution?**
If yes, the WORM evidence store, custody ledger and disclosure pack are
load-bearing and should stay in the MVP. If it is purely internal
intelligence that will never be evidence, you can defer chain of custody
and save real time in Phase 1.

> **Answered 2026-07-24: YES — prosecution-grade, Canada + US** (decision
> 13). WORM store, custody ledger and hash verification stay in Phase 1.

**3. Expected case size.**
My assumption: hundreds to a few thousand nodes per case, tens of thousands
at the extreme. If you expect hundreds of thousands in a single case, the
rendering and analytics strategies both change — server-side layout and
level-of-detail rendering become necessary rather than optional.

**4. Team size and concurrency.**
Under ten analysts and you can skip real-time collaborative editing and use
optimistic locking. Above that, you need presence and conflict resolution
on the graph, which is a substantial piece of work best planned for now.

**5. Cross-case pivoting.**
Should an analyst see that a wallet in Case A also appears in Case B they
have no access to? A "there is a match, request access from the owner"
signal is enormously valuable and also a compartment leak. My schema
supports it — selector indexes are global — but I have not decided the
policy. This is a genuine tradeoff and needs a human answer.

**6. Deployment environment.**
Air-gapped, on-prem, or cloud? Air-gapped kills the collection layer and
changes everything about how updates and threat feeds work. Cloud raises
questions about where evidence physically sits.

**7. Existing Jira instance.**
Cloud or Data Center? Cloud means webhook-based inbound and OAuth 2.0 3LO.
Data Center means you can be more relaxed about network position but
webhooks need a reachable endpoint. You mentioned prior work here, so you
may already have the pattern.

**8. Do you need Telegram at all in the MVP?**
It is by far the highest-effort and highest-risk adapter — persona
management, FLOOD_WAIT, session security, overt join events. If forums
carry most of your value, RSS plus XenForo gets you a working pipeline in
half the time and proves the model before you take on MTProto.

> **Answered 2026-07-24:** evidence **capture** yes, automated
> **monitoring** no (decision 18). Analysts file Telegram exports as
> evidence with full custody; the MTProto monitoring adapter stays
> deferred and monitoring is handwork for now.

**9. Language coverage.**
Russian-language forums are central to this domain. Do you need
translation, transliteration handling for handles (Cyrillic/Latin
homoglyph confusion is a real attribution problem), and Cyrillic-aware
stylometry? This affects the extractor and embedding choices, so it is
better decided now.

**10. Who reviews the reviewers?**
I have modelled `SECURITY_OFFICER` as separate from analysts. In a small
team that may be one person wearing both hats, which defeats the
separation. If so, decide now whether to enforce it or accept the risk
explicitly rather than discovering the gap in an audit.
