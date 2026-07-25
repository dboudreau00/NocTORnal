# 09 — Roadmap

Sequenced so that each phase is independently useful. The ordering
constraint that matters: **the graph and assertion layer must work end to
end before collection is switched on.** Pointing a firehose at a half-built
model produces a landfill you then have to clean by hand.

---

## Phase 0 — Foundation (week 1)

- [ ] Monorepo, Docker Compose (Postgres, Redis, MinIO, MailHog)
- [ ] Alembic wired, `schema.sql` split into initial migrations
- [ ] Ontology package: single source of truth → generated Py + TS types
- [ ] Auth: password + TOTP, sessions, Argon2id
- [ ] RBAC/ABAC gate as one function with full test coverage
- [ ] Audit log with hash chaining, plus a chain verification job
- [x] CI: lint, test, migration round-trip, ontology drift and source
      hygiene (decision 42). **No typecheck** -- there are no type
      annotations to check against yet.

**Done when:** a user can register, enrol TOTP, log in, and every action
appears in a verifiable audit chain.

---

## Phase 1 — Graph core (weeks 2–3)

- [ ] Case CRUD with mandatory legal basis and retention
- [ ] Node/edge CRUD against the ontology, with type validation on edges
- [ ] Assertion layer — no graph write path exists without one
- [ ] Selector storage, normalisers per type, exact-match lookup
- [ ] Evidence upload → MinIO WORM, hashing, custody ledger
- [ ] Evidence linking to nodes and edges
- [ ] Tags and node sets
- [ ] Full-text search over nodes and evidence

**Done when:** an analyst can build a case entirely by hand, and every edge
answers "why do we believe this?" in one click.

This is the point to stop and actually use it on a real case for a week
before building anything else. Everything downstream assumes this model is
right, and a week of real use will find the places it is not.

---

## Phase 2 — Sociogram (weeks 4–5)

- [ ] Projection model and the four presets
- [ ] Graph API: neighbourhood, path, subgraph, as-of queries
- [ ] sigma.js canvas with ForceAtlas2 in a worker
- [ ] Full visual encoding per `docs/06-interface.md`
- [ ] Layout persistence and pinning
- [ ] Inspector panel: entity, assertions, evidence, backlinks
- [ ] Local metrics (degree, clustering, k-core) live
- [ ] WebSocket push for graph changes
- [ ] Command palette

**Done when:** a 2,000-node case renders at 60fps and an analyst can find a
broker visually.

---

## Phase 3 — Analytics (week 6) — SHIPPED 2026-07-25

- [x] igraph projection materialisation — `analytics.py`, pure and
      database-free, fed by `GraphService.project()`. Run **synchronously in
      the API**, not in a separate worker: see decision 30 for the reasoning
      and the accepted caveat.
- [x] Global centralities, cached on graph hash — betweenness (exact under
      3k nodes, Brandes pivot sampling above), harmonic closeness,
      eigenvector over the positive subgraph. Cache is scoped to the
      caller's visibility (decision 31).
- [x] Leiden communities
- [x] Burt's constraint, effective size, efficiency and hierarchy
- [x] Cut vertices and bridges
- [x] Key player (KPP-Neg) with fragmentation preview, reported against the
      top-n by betweenness so the difference is visible rather than claimed
- [x] Signed-network balance and unbalanced triad surfacing, plus contested
      dyads (a pair carrying both a vouch and an accusation)
- [x] Metric panel with rank, percentile and approximation flags
- [x] Trust decay at projection time (docs/03), never mutating stored weight
- [x] Per-node metric history, so a rising betweenness trend is visible

**Done when:** the tool answers "who holds this network together" with
something better than degree count. — **Met.** On `OP-LATTICEWORK-26`
(`bootstrap.py demo-network`), the optimal 3-actor removal set fragments the
network to F=0.727 in three equal crews, where the top 3 by betweenness
reach only F=0.409 — a different, better answer, which is exactly the claim
in docs/03.

Deliberately NOT built, and why:

- **A separate analytics worker process.** Decision 30.
- **Bipartite projection to one-mode with Newman weighting.** The Financial
  and Communication presets are two-mode; the response warns rather than
  silently rewriting them (decision 33).
- **Cohesive blocking, CONCOR, regular equivalence, correspondence
  analysis.** docs/03 lists them; none is needed to answer the phase's
  question, and each is a large piece of work.
- **Change-point detection and metric time series in the UI.** The history
  endpoint exists and is tested; nothing charts it yet.
- **Per-case trust-decay default.** The half-life is a request parameter
  stored on the projection; `core."case"` has no column for a default.

---

## Phase 4 — Collection (weeks 7–9)

- [ ] Adapter interface and scheduler with jitter and rate limiting
- [ ] RSS adapter (simplest, proves the pipeline end to end)
- [ ] Persona vault: envelope encryption, egress binding, status lifecycle
- [ ] XenForo adapter with quote and signature stripping
- [ ] MyBB adapter
- [ ] Telegram MTProto adapter with FLOOD_WAIT handling
- [ ] Document bucket: normalise, dedupe, version, index, embed
- [ ] Selector extractors with offsets
- [ ] Watch matching → watch hits
- [x] **Proposal model and the human review gate** (`proposals.py`,
      decision 39) — invariant 3 is now enforced by the extractor-facing
      class being *unable* to write the graph, rather than by remembering
      not to. Accepting applies through GraphWriteService, so the assertion
      is atomic and the resulting edge is born inferred.
- [x] Triage queue (API: `GET/POST /cases/{id}/proposals/...`). **Not yet
      keyboard driven, and not yet in the UI** — the endpoints exist and are
      tested; nothing renders them.
- [ ] Proposal generation *from real extractions* — nothing extracts yet,
      so nothing writes proposals outside tests
- [ ] Parser health checks and drift alerting

**Done when:** a watch on a real forum fills the bucket for a week without
silent breakage, and triage is a pleasant hour rather than a grim one.

---

## Phase 5 — Notification and integration (week 10)

- [x] **Classification egress gate, one function, called everywhere**
      (`egress.py`, decision 38). Destination-aware, fails closed, and
      evidence export now goes through it instead of its own copy.
- [ ] SMTP with digest, suppression, quiet hours, escalation
- [ ] In-app notification centre
- [ ] Jira: outbound task creation, inbound status webhook, TLP ceiling
- [ ] Outbound webhooks with HMAC
- [ ] Admin surface for integration config and delivery logs

---

## Phase 6 — Tradecraft and hardening (weeks 11–12)

- [ ] Timeline scrubber and temporal replay
- [x] **Entity merge with reversal** (`merges.py`, Alembic 0027,
      decision 41), step-up gated, with an entity-resolution panel in the
      inspector that offers only same-type candidates and lists every
      merge with a one-click reversal. **Dual control is NOT built** --
      one cleared analyst with a fresh second factor can merge alone.
- [ ] ACH matrix and assumptions register
- [ ] Report builder with TLP-aware redaction
- [ ] Retention and purge jobs with tombstones
- [ ] WebAuthn
- [ ] Break-glass and dual-control flows
- [ ] Security review: SSRF, CSP, rate limits, RLS
- [ ] Backup and restore rehearsal

---

## Phase 7 — Comms channels (concept, `docs/10`)

- [ ] `comms.platform` reference seeded, durable-selector mapping enforced
- [ ] Contact-block parser with role attribution and the service stoplist
- [ ] `CLAIMED` vs `CONFIRMED` control, PGP signature verification
- [ ] Device fingerprint nodes from OMEMO / Matrix device keys
- [ ] Conversation and participant model with mandatory provenance class
- [ ] Forum PM capture where a persona is a party
- [ ] Co-participation projection into the sociogram

**DECIDED (2026-07-25): message-level capture.** See decision 35. Metadata
would have been cheaper, but content is what a disclosure obligation and a
prosecution turn on, and a channel that has since been deleted cannot be
re-captured. The accepted costs: storage scales with traffic rather than
with the number of parties, every captured message is personal data inside
the retention and minimisation regime, and the Phase 5 TLP egress gate
stops being advisory.

## Phase 8 — Sample handling (concept, `docs/11`)

- [ ] Separate-origin sample service, download-only, no rendering
- [ ] Encrypted-at-rest storage keyed by SHA-256, EDR exclusions documented
- [ ] Quarantine → triage → RE queue with `MALWARE_ANALYST` as a distinct role
- [ ] Static triage: hashes, imphash, ssdeep, TLSH, YARA
- [ ] Fuzzy-hash clustering surfaced as graph edges
- [ ] Prohibited-content screening and the `REJECTED` path
- [ ] Detonation as an authorised, exposure-aware action

**BLOCKED — NOT DECIDED (2026-07-25).** There is no prohibited-content
policy, so no part of this phase may be built past the point where it could
accept a file. See decision 36 and the warning at the top of the README:
a store of attacker-supplied binaries will eventually receive material whose
possession alone is an offence, the handling rules differ between the two
target jurisdictions, and finding that out after the first ingest is a legal
problem rather than a technical one. Everything through Phase 7 is
unaffected; nothing in the current build stores a sample.

## Phase 9 — Ingest API (concept, `docs/12`)

- [ ] `noct_sk_` key issuance, HMAC storage, mandatory expiry, rotation overlap
- [ ] Ingest endpoint: async 202, idempotency, raw-persist-before-parse
- [ ] Format detection and schema mapping per key
- [ ] Category classifier and the correction loop
- [ ] Triage scoring with watchlist dominance
- [ ] Simhash near-duplicate suppression
- [ ] Dead-letter queue with repair and replay
- [ ] Stealer-log compartment, masking and minimisation

**Decide first:** stealer logs in scope? If yes, the compartment and
minimisation policy comes before any ingest code.

---

## Later

Link prediction and stylometry (hypotheses only) · disclosure pack
generator · STIX/MISP export · cross-case pivoting with compartment
respect · blockchain analytics integration · translation for
non-English sources · mobile read-only view · CONCOR blockmodelling ·
change-point detection on network structure

---

## Handing tasks to Claude Code

Work one phase at a time, one checklist item per session where the item is
substantial. Useful opening prompt shape:

> Read CLAUDE.md, docs/01-domain-model.md and db/schema.sql. Implement
> Phase 1 item "Assertion layer." Requirements: no code path writes to
> `node` or `edge` without creating an `assertion` in the same
> transaction. Write the failing test first, named for invariant 1 in
> CLAUDE.md. Show me the migration before you apply it.

Pinning it to the invariant by number is worth doing — it keeps the
non-negotiables in context and gives the test a name that explains itself
in six months.
