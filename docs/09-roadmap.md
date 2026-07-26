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

## Phase 4 — Collection — BUILT 2026-07-25 (decision 53)

- [x] **Adapter interface and scheduler** with symmetric jitter and
      per-source `max_rps`. **Nothing loops** — `due_sources()` reports and
      `run_once()` acts.
- [x] **RSS adapter**, which refuses any feed carrying a DOCTYPE.
- [x] **Persona vault**: envelope encryption, egress-separation check,
      status lifecycle with terminal burn. `use()` is a context manager and
      there is deliberately **no `get_secret()`** (invariant 7).
- [ ] XenForo, MyBB and Telegram MTProto adapters. Each needs a real target
      and a persona to develop against, both of which are authorisation
      questions (docs/16 L3) rather than coding ones.
- [x] **Document bucket**: dedupe on content, version rather than overwrite.
      No embeddings.
- [x] **Watch matching → watch hits**, with suppression applied before the
      row is written.
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
- [x] **In-app notification centre** (`notifications.py`, Alembic 0029,
      decision 46) with an Inbox rail tab, unread badge, read/acknowledge
      and per-channel preferences. Wired to the two events the docs name:
      the **case-owner notification on merge** docs/01 requires by name,
      and approval request/decision, without which dual control is a merge
      button that does not work.
- [x] **SMTP with digest, suppression and quiet hours** (`transports.py`).
      Quiet hours defer rather than drop; priority 1 overrides them.
      Escalation of an unacknowledged priority-1 hit is NOT built.
- [x] **Outbound webhooks with HMAC** (`transports.py`), same redaction
      split as email.
- [ ] Jira: outbound task creation, inbound status webhook, TLP ceiling.
      The webhook transport it would specialise exists and is signed; what
      is missing is the Jira API mapping and a Jira to verify against.
- [ ] Admin surface for integration config and delivery logs. The
      `notify.delivery` ledger exists and records every refusal and
      suppression with a reason; nothing renders it.
- [ ] **No worker process.** `POST /notifications/dispatch` drains the
      outbox and is called by an operator, a cron entry or a test
      (decision 46, following decision 30).

---

## Phase 6 — Tradecraft and hardening (weeks 11–12)

- [ ] Timeline scrubber and temporal replay
- [x] **Entity merge with reversal** (`merges.py`, Alembic 0027,
      decision 41), step-up gated, with an entity-resolution panel in the
      inspector that offers only same-type candidates and lists every
      merge with a one-click reversal. **Dual control landed 2026-07-25**
      (decision 44, Alembic 0028): a generic four-eyes mechanism, wired to
      merge as a per-case switch that defaults to OFF because a merge is
      reversible and docs/05 scopes dual control to the irreversible.
- [x] **ACH matrix** (`ach.py`, decision 48), ranked by inconsistency
      rather than support, with diagnosticity scoring and Admiralty
      weighting. The **assumptions register** is NOT built.
- [x] **Report builder with TLP-aware redaction** (`reports.py`,
      decision 49). Structural redaction through the access gate's own code
      path; the document's mark follows its contents; release goes through
      the egress gate and is audited both ways.
- [ ] Retention and purge jobs with tombstones. **The four-eyes mechanism
      they need already exists** and `evidence.purge` is registered as an
      unconditional dual-control operation (decision 44).
- [ ] WebAuthn. Recovery codes landed in Phase 3; hardware keys did not.
- [~] **Dual control landed** (decision 44). **Break-glass has NOT**:
      `iam.break_glass` exists in the schema and nothing writes it.
- [~] Security review: **rate limits done** (decisions 43, 45, after an
      adversarial pass found 12 defects). SSRF, RLS and a non-owner DB role
      remain.
- [ ] Backup and restore rehearsal

---

## Phase 7 — Comms channels — BUILT 2026-07-25 (decision 54)

- [x] **`comms.platform` reference seeded** (15 platforms), durable-selector
      mapping enforced by `normalise()`. Tox → first 64 hex; Telegram →
      numeric id, never `@username`; SimpleX → no identifier, said out loud.
- [ ] Contact-block parser with role attribution and the service stoplist.
- [x] **`CLAIMED` / `OBSERVED` / `CONFIRMED`**, and CONFIRMED must state its
      method. PGP signature verification itself is NOT built.
- [x] **Device fingerprints against DEVICE nodes**, reported as a LEAD and
      never as a merge.
- [x] **Conversation and participant model with mandatory provenance
      class**, and a CHECK requiring an authority for anything not obtained
      by being a party or from an open room.
- [x] **Minimisation** that drops bodies and keeps the contact graph.
- [ ] Co-participation projection into the sociogram.

**DECIDED (2026-07-25): message-level capture.** See decision 35. Metadata
would have been cheaper, but content is what a disclosure obligation and a
prosecution turn on, and a channel that has since been deleted cannot be
re-captured. The accepted costs: storage scales with traffic rather than
with the number of parties, every captured message is personal data inside
the retention and minimisation regime, and the Phase 5 TLP egress gate
stops being advisory.

## Phase 8 — Sample handling — BUILT 2026-07-25 (decision 47)

- [x] **Separate-origin sample service, download-only, no rendering.** The
      origin split is a RUNTIME refusal, not a deployment note: `download()`
      refuses unless `NOCTORNAL_SAMPLE_ORIGIN` is set and the request
      arrived at it.
- [x] **Encrypted-at-rest storage keyed by SHA-256.** Never the
      attacker-controlled filename. Bytes re-verified on every read, failing
      closed. EDR exclusions documented in `samples.py`.
- [x] **Quarantine → triage → RE queue with `MALWARE_ANALYST` as a distinct
      role** that grants no case access, and case roles that cannot download.
- [~] **Static triage:** sha256/sha1/md5, structural file typing and Shannon
      entropy. **imphash, ssdeep, TLSH and YARA are NOT computed** — each
      absence is recorded on the row as a gap with a reason.
- [ ] Fuzzy-hash clustering surfaced as graph edges. Blocked on the fuzzy
      hashes above.
- [~] **The `REJECTED` path is built** — it destroys the bytes and the data
      key and keeps the row saying that something was rejected and why.
      **Automated prohibited-content screening is NOT**: there is no
      authorised hash set, so rejection is a human act.
- [~] **Detonation is an authorised, exposure-aware RECORD.** A non-private
      target needs a named authoriser and a note, in a DB constraint.
      **Nothing is submitted to any sandbox** — docs/11 says integrate
      rather than build, and no integration exists.

**UNBLOCKED BY OPERATOR DIRECTIVE (2026-07-25), NOT BY A POLICY.**
Decision 47 supersedes decision 36. The reasoning behind the block has not
changed — a store of attacker-supplied binaries will eventually receive
material whose possession alone is an offence, the handling rules differ
between the two target jurisdictions, and finding that out after the first
ingest is a legal problem rather than a technical one. What changed is that
the block became a refusal with a named condition: **the build accepts
nothing until an operator declares a prohibited-content policy reference and
a designated person.** That is a declaration the software records, not one
it can verify. Counsel must review any deployment before it is used in any
absolute sense.

## Phase 9 — Ingest API — BUILT 2026-07-25 (decision 52)

- [x] **`noct_sk_` key issuance**, HMAC-with-pepper storage (not Argon2),
      mandatory capped expiry, rotation overlap, IP allowlist, and
      write-only scopes enforced by a CHECK (invariant 11).
- [x] **Raw-persist-before-parse** and idempotency dedupe. The HTTP 202
      endpoint itself is not wired; `accept()` is.
- [x] **Format detection by sniffing**, never by declared Content-Type.
- [x] **Category classifier** where structure beats the declaration, with
      the confidence kept so a correction is visible as one.
- [x] **Triage scoring** with the watched-selector term dominant.
- [x] **Simhash near-duplicate suppression.**
- [x] **Dead-letter queue with repair and replay**, and the original
      fragment survives the replay.
- [x] **Stealer-log compartment and masking.** Free-text PII search is
      impossible by construction; reveal needs a live two-human
      authorisation. **Minimisation policy is a legal determination and is
      NOT resolved — docs/16 L2.**

**DECIDED 2026-07-25: stealer logs ARE in scope** (operator directive,
decision 52). The compartment is resolved in the schema. The minimisation
policy and the lawful basis for holding data about thousands of uninvolved
people are NOT resolved and are BLOCKING — see docs/16 L2.

---

## Later

Link prediction and stylometry (hypotheses only) · disclosure pack
generator · STIX/MISP export · cross-case pivoting with compartment
respect · blockchain analytics integration · translation for
non-English sources · mobile read-only view · CONCOR blockmodelling ·
change-point detection on network structure

---

## Handing tasks to a contributor

Work one phase at a time, one checklist item per session where the item is
substantial. Useful opening prompt shape:

> Read CONVENTIONS.md, docs/01-domain-model.md and db/schema.sql. Implement
> Phase 1 item "Assertion layer." Requirements: no code path writes to
> `node` or `edge` without creating an `assertion` in the same
> transaction. Write the failing test first, named for invariant 1 in
> CONVENTIONS.md. Show me the migration before you apply it.

Pinning it to the invariant by number is worth doing — it keeps the
non-negotiables in context and gives the test a name that explains itself
in six months.
