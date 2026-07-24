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
