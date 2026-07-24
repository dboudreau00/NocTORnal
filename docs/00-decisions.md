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
| 19 | Stealer logs in scope but SEGREGATED — never inside the core evidence store (2026-07-24) | Stealer logs are bulk third-party PII, the most likely route to a data-protection incident. They upload to a samples-style segregated environment (separate origin/bucket/compartment, docs/11 model): metadata and extracted selectors may flow to the graph as assertions; raw dumps never enter `core.evidence`. PII masking and minimisation land before any stealer ingest code | High — once raw dumps sit in the case store, retention/disclosure obligations attach and cannot be unwound |

---

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
