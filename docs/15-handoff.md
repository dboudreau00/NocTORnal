# 15 — Handoff

Everything a fresh session needs to continue this build. Written 2026-07-25
after Phases 0–2 shipped; **updated 2026-07-25 after Phase 3 shipped**. Read
this, then `CONVENTIONS.md`, then `docs/14-enhancement-map.md`. What to do next is
at the bottom.

> **Phases 0-3 complete; Phases 4, 5 and 6 partially built.** 421 tests
> pass. The loop an analyst can now actually run: paste text -> selectors
> extracted with offsets -> proposals -> keyboard triage -> graph ->
> structural analysis -> retract a source and watch it dissolve. See the
> "What was built after Phase 3" section below for the second batch.
>
> **Phase 3 proper.** `apps/api/src/noctornal_api/analytics.py` (the maths,
> database-free) and `analytics_runs.py` (cache, persistence, audit), exposed
> at `/api/v1/cases/{id}/analytics`, with an Analysis tab in the UI. 304 tests
> pass. Run `bootstrap.py demo-network` for a case with structure worth
> analysing — `demo-case` is a 7-node star and every Phase 3 metric is
> degenerate on it. Decisions 30–33 in `docs/00-decisions.md` record the four
> judgement calls, including the one that matters most: analytics run
> **synchronously in the API**, not in a separate worker.

## What this is

NocTORnal is a HUMINT / social-network-analysis platform for cybercrime
investigation: analysts build a graph of criminal actors, personas, groups
and the trust between them, every element traceable to graded evidence with a
chain of custody. Comparable to Maltego, i2, SL Crimewall, with UCINET-grade
SNA maths. Named 2026-07-24; the scaffold's codename was "lattice".

**Three ideas everything follows from** (docs/01): a handle is not a person
(`IDENTITY` vs `PERSON`, joined by a reversible confidence-scored edge);
nothing is a fact (every element traces to an `assertion` with an Admiralty
grading); machines propose, analysts dispose (extractors write `proposal`
rows, never graph elements).

## Run it

```bash
powershell -ExecutionPolicy Bypass -File "scripts\launch.ps1"
```

`-SkipDocker` if the stack is up, `-Port N` to move it. UI at
<http://127.0.0.1:8000/ui/>. Full detail in `QUICKSTART.md`.

Sign in with `.venv\Scripts\python scripts\bootstrap.py session --email
YourEmail@mail.com` — prints a URL that lands in the UI already
authenticated. `bootstrap.py` also has `create-user`, `demo-case`,
`list-users`, `unlock`, `reenrol-totp`, `totp-code`, `totp-diagnose`.

```bash
.venv\Scripts\python -m pytest packages/ontology/tests apps/api/tests -q
```

254 tests. Postgres legs gate on `DATABASE_URL`, evidence legs additionally
on `MINIO_ENDPOINT`, so the suite degrades to unit-only without the stack.

## Shape of the repo

```
docs/00-15            decisions, domain model, architecture, analytics,
                      collection, security, interface, integrations,
                      governance, roadmap, concept layer (10-12),
                      differentiators, enhancement map, this file
db/migrations/        Alembic 0001-0025 — the schema of record
db/schema.sql         readable mirror of the same schema (kept in sync)
db/seed_ontology.sql  readable mirror of the ontology seed
packages/ontology/    THE vocabulary: definition.py generates TS + SQL;
                      25 selector normalisers
apps/api/src/noctornal_api/
  security/           passwords, totp, sessions, tokens, envelope, access
  stores.py           Postgres impls + the access-context resolver
  graph.py            GraphWriteService — the ONLY sanctioned graph write
  projections.py      projections, ego, paths, local metrics
  cases.py selectors.py evidence.py curation.py
  http/               app factory, deps (auth + gate), 7 routers, static UI
scripts/              bootstrap.py, launch.ps1, launch.sh
infra/                docker-compose (Postgres+pgvector, Redis, MinIO,
                      OpenFGA, NATS, Mailpit)
```

Roughly 8.4k lines of API, 2.4k of migrations, 3.3k of tests, 2.7k of docs.

## How each invariant is actually enforced

Not aspirations — these have tests named after them.

| # | Invariant | Enforcement |
|---|---|---|
| 1 | Nothing is a fact | **Database.** Two deferred constraint triggers (0022): a node/edge must have an assertion by commit, AND the last assertion of a live element cannot be deleted or repointed. Closes the `SET CONSTRAINTS ALL IMMEDIATE` and later-transaction bypasses. |
| 2 | A handle is not a person | `SAME_AS` may not cross the IDENTITY/PERSON layer (edge validator, 0018). Attribution is `ATTRIBUTED_TO` only. |
| 3 | Machines propose | `proposal` table exists; no extractor is built yet, so nothing writes it. |
| 4 | Inferred edges distinct | `is_inferred` renders dashed and is excluded from projections unless opted in. |
| 5 | History superseded | `retracted_at`/`superseded_at` are row-preserving updates; trigger 2 deliberately ignores them so retraction can dissolve an element from the live graph while history survives. |
| 6 | Audit append-only | `audit.event` hash-chained with advisory-lock serialisation, UTC-canonical delimited hash over every column, pinned `search_path`, plus append-only triggers. |
| 7 | Credentials never leave the collector | `collection_account.secret_*` is never selected outside the auth path; TOTP secrets sealed AES-256-GCM, decrypted lazily only on the success path. |
| 8 | TLP gates egress | `export()` refuses AMBER_STRICT/RED. The destination-aware gate is Phase 5. |
| 9 | Durable identifiers | `TOX_PK` (64-hex) is strong, `TOX_ID_FULL` weak; Telegram numeric strong, `@username` weak. Tested with a rotated-nospam regression test. |
| 10 | Samples never render | No sample handling built (Phase 8). |
| 11 | Ingest keys write-only | No ingest API built (Phase 9). |
| 12 | Nothing silently dropped | `ingest.dead_letter` exists in the concept schema; no ingest yet. |

## What is built

**Phase 0.** Alembic owns the schema (initdb loads only extensions, which
need superuser). Ontology package generates TypeScript and SQL from one
definition, with `--check` for CI drift. Auth: Argon2id (t=3, m=64MiB, p=4),
RFC 6238 TOTP (verified against the spec's test vectors) with replay
protection as a **DB compare-and-set**, opaque server-side sessions (12h
absolute / 30min idle). The five-part access gate is one `evaluate()`
function with a test that fails if any check is removed.

**Phase 1.** Assertion layer (see invariant 1). Case CRUD with governance
guards. Selector storage wired to the ontology normalisers. Evidence: WORM
object-lock in **COMPLIANCE** mode, SHA-256 + BLAKE3, read-back verified at
ingest, **re-verified on every read** and failing closed, with an
append-only hash-chained custody ledger. Tags, node sets, full-text search.

**Phase 2.** Four projection presets (Trust/Communication/Financial/All),
ego networks, shortest paths, `as_of` timeline scrubber, local metrics
(degree, weighted, positive/negative separately, clustering, k-core), saved
layouts with pinning, ⌘K palette, and the inspector answering "why do we
believe this" with the Admiralty grading behind each claim.

**HTTP layer.** 31 endpoints under `/api/v1`, problem+json, security
headers, CSRF double-submit for cookie auth, and an analyst UI (plain
HTML/CSS/JS, no build step) under a CSP that still forbids inline script.

## Gotchas that cost real time

- **uvicorn does not run with `--reload`.** A Python change is invisible
  until restart; new routes return a plain `{"detail":"Not Found"}` while
  `create_app().openapi()` lists them happily. This wasted a debugging round.
- **Migrations must use** `op.get_bind().connection.driver_connection.execute(sql)`.
  SQLAlchemy's `exec_driver_sql` triggers psycopg3 `%`-placeholder parsing,
  which chokes on the `RAISE 'edge %: ...'` format strings in triggers.
- **Write/Edit tools corrupt non-ASCII literals into NUL bytes on this
  machine.** Keep Python and JS source ASCII-only and use `\uXXXX` escapes.
  Also: a `"\b"` in a non-raw Python replacement string is a *backspace* — it
  silently mangled a documented command path once.
- **Evidence and custody are WORM/append-only by design**, so test teardown
  must `ALTER TABLE core.evidence_custody DISABLE TRIGGER USER` inside the
  cleanup transaction.
- **Deferred triggers fire at commit**, so deleting assertions and their
  nodes must happen in ONE transaction or cleanup trips invariant 1.
- **`now()` cannot appear in a partial-index predicate** (not IMMUTABLE) —
  this was a load-blocker in the original scaffold.
- **This host's clock has never reached a time server** (`w32tm /query
  /status` → `Leap Indicator: 3`, `Source: Local CMOS Clock`). TOTP is a
  function of absolute Unix time, so if the host disagrees with a phone by
  more than ~60s no code can ever match. Diagnose, do not guess:
  `bootstrap.py totp-diagnose --email <e> --code <six> --next-code <next>`
  distinguishes clock offset from a wrong secret. `bootstrap.py session` is
  the way in regardless.

## Decisions

`docs/00-decisions.md` holds 29 numbered decisions with the reasoning and
the cost of reversal. The ones a new session most needs:

- **13** Prosecution-grade evidence, **Canada + US** (FRE 901/902(13)-(14);
  Canada Evidence Act ss. 31.1-31.8). WORM store, custody ledger and hash
  verification are load-bearing, not optional.
- **16** Operating context: **law enforcement primary**, private CTI
  secondary.
- **18** Telegram **capture** in the MVP; automated monitoring deferred.
- **19** Stealer logs in scope but **segregated** — never inside
  `core.evidence`; metadata and selectors may reach the graph, raw dumps
  never.
- **22** `TRANSACTION` is a *proven criminal on-chain transaction*, with
  wallet legs, keeping the money graph two-mode.
- **17** Alembic owns the schema; `db/schema.sql` is a mirror to keep in sync.

Still open (docs/00): venue-scoped `FORUM_UID`, endpoint-aware `BANNED_BY`,
two-step MFA ticket, expected case scale.

## Phase 3 — what was built (2026-07-25)

Goal (docs/09): *the tool answers "who holds this network together" with
something better than degree count.* Met.

`analytics.py` holds the maths and **never touches the database**: it takes a
`Subgraph` from `GraphService.project()` — already clearance-filtered — and
returns numbers. That is what makes it testable against hand-computed values,
and what makes it impossible for a metric to widen what a caller can see.
`analytics_runs.py` owns everything stateful: the cache, the `metric_run`
lifecycle, `node_metric` / `community_assignment`, and the audit event.

What it computes, all from one materialisation: betweenness, harmonic
closeness (not classical — undefined on a disconnected graph, and criminal
networks are routinely disconnected), eigenvector over the **positive
subgraph only** (being accused by a big name does not confer standing),
Burt's constraint / effective size / efficiency / hierarchy, Leiden
communities, cut vertices, bridges, signed structural balance with unbalanced
triads and contested dyads, and KPP-Neg key player. Rank and percentile sit
beside every value; the graph is treated as **simple and undirected** for
structure, with directed signed degree reported separately because vouches
received and vouches given mean opposite things.

Four judgement calls are recorded as decisions 30–33 in `docs/00-decisions.md`.
The load-bearing one: **analytics run synchronously in the API process, not in
the Zone B worker docs/02 describes.** A queue would add a process, a
dependency and a progress UI without changing a number at this scale
(2,000 nodes / 6,000 edges measured at 1.15 s). The seam is deliberate — the
compute layer is pure, so moving it later is a change of caller, not of
algorithm. The accepted caveat was that this is a CPU-bound path behind a
non-step-up permission with rate limiting deferred -- **that caveat is now
closed**: `analytics.suite` and `analytics.key_player` carry their own
per-user limits (decision 43), and the key-player bucket is smaller than the
suite's because KPP-Neg is combinatorial in the removal-set size.

### Three bugs found and fixed on the way in

These were pre-existing and none was in the Phase 3 brief.

- **Retraction was cosmetic.** Decision 24 deliberately scoped live
  provenance as a projection property rather than a database constraint —
  and the projection never implemented it. A retracted assertion showed a
  RETRACTED chip while its node kept full degree, and Phase 3 would have
  named takedown targets from withdrawn evidence. `project()` now requires a
  non-retracted assertion on both nodes and edges. Zero assertions were
  retracted when this landed, so no existing number moved.
- **`truncated` was computed and dropped.** `project()` sets it; `metrics()`
  returned `p.describe()`, which has no such key. A metric over a cut-off
  node set was indistinguishable from a complete one. It is now surfaced,
  and key player **refuses outright** on a truncated projection rather than
  naming people for removal from a graph that is not the case.
- **A fail-open default in my own migration**, caught by an adversarial
  review before it shipped. `visibility_compartments text[] NOT NULL DEFAULT
  '{}'` would have made a forgotten write match exactly what an analyst
  holding no compartments looks up with. Both visibility columns are now NOT
  NULL with no default, so a forgotten write is a loud failure.

### Gotchas specific to this layer

- **`igraph` has no `estimate_betweenness` in 1.0.** Pivot sampling goes
  through `betweenness(sources=...)` scaled by `n/k`.
- **`eigenvector_centrality` accepts negative weights and returns nonsense**
  with only a warning. It is computed over positive ties, and flagged when
  the positive graph is disconnected, because the values are then comparable
  only within a component.
- **`constraint()` returns NaN for isolates.** NaN is not valid JSON and 0.0
  is a lie — it would rank an isolate as the best broker in the case. Both
  the API and the UI carry `null` through as an em dash.
- **`demo-case` cannot test any of this.** It is a 7-node star: no triangles,
  so balance, clustering and Leiden are all degenerate, and betweenness is
  trivially maximal at the centre. Use `bootstrap.py demo-network`.
- **igraph and leidenalg ship abi3 wheels**, so they install on this box's
  CPython 3.13 with no build toolchain, despite the docs assuming 3.12.

## What was built after Phase 3 (2026-07-25)

The enhancement map's E-items, the Phase 2 layout debt, and the first
slices of Phases 4 and 5. Decisions 34-39 carry the reasoning.

**Evidence and retraction (E1-E3, decision 34).** An assertion can now
carry its exhibit at the moment the claim is made -- `evidence_id` had
existed unused since Phase 1, which is how the first real session produced
fourteen assertions and zero exhibits. The projection reports
`has_evidence` per element, unevidenced entities render with a hollow core,
unevidenced ties render faded, and case-level coverage is a headline number
that reads red at zero. Retraction is exposed in the inspector and, because
Phase 3 added the live-provenance filter, retracting the last live
assertion visibly dissolves the element from the live graph. Verified: one
retraction split the demo network from one component into two.

**Recovery codes (E4).** docs/05 specified them and they were never built.
Told apart from a TOTP code by SHAPE so login stays single-step and gains
no oracle; single use enforced by an atomic `array_remove` guarded on the
hash still being present. `bootstrap.py recovery-codes` is the out-of-band
path for the person who by definition cannot complete step-up.

**Layout worker (U1, decision 37).** Hand-written ForceAtlas2 with
Barnes-Hut in a Web Worker, because the CSP is `script-src 'self'` with no
bundler and adopting a build step is a decision that should not arrive as a
side effect. 400 nodes settle in ~1s off-thread. Note for whoever measures
it next: **a hidden browser tab clamps `setTimeout` to ~1000ms**, so
"main-thread lag" readings taken in a background pane are measuring Chrome,
not your code. Count messages and repaints instead.

**Egress gate (Phase 5, decision 38).** The one function docs/07 requires.
Pure, fails closed, destination-aware. Evidence export now calls it instead
of its own drifting copy.

**Proposals (Phase 4 core, decision 39).** Invariant 3 enforced by class
shape: the extractor-facing class holds no `GraphWriteService` and cannot
reach the graph. Accepting goes through `GraphWriteService`, so the
assertion is atomic and an accepted edge is born inferred.

### Third batch (same day): capture, triage, merge

**Manual capture and triage (Phase 4, decision 40).** The proposal
pipeline had no producer and no interface, so invariant 3 was still a
claim about the schema. `extraction.py` lands pasted text as a
`collect.document` deduped on content hash, runs regexes that write
`collect.extraction` rows WITH character offsets, and raises one proposal
per new value carrying the matched span and the sentence around it. The
Triage tab is keyboard driven (J/K to move, A/R/D to dispose) because
docs/09 wants triage to be "a pleasant hour rather than a grim one".

The extractor earns its keep by what it REFUSES: `build 10.2.14.3` is not
an IPv4, a 64-hex string is not also a SHA-1 and an MD5, an email is not
also a bare domain, an invalid-length `.onion` is not an onion, and
ordinary English yields nothing. Those are most of its tests, because a
bad extractor does not fail loudly -- it fills the queue with plausible
junk until an analyst stops reading it. It proposes SELECTOR nodes only,
never PERSON: attribution is an assessment a human makes (invariant 2).

**Entity merge (Phase 6, decision 41, Alembic 0027).** A ledger, not a
flag. Re-pointing an edge destroys the original fact, so `core.node_merge`
+ `node_merge_edge` record every moved endpoint and reversal is a restore
rather than a re-derivation. IDENTITY may never merge into PERSON --
that is an ATTRIBUTED_TO edge carrying a confidence, and collapsing the
gap destroys what the model exists to preserve. Step-up gated.

**Sociogram resize.** Two real defects found from use: the view never
recentred on resize (so maximising just added margin), and below ~900px
the canvas collapsed to ZERO height and the graph vanished while its
controls stayed on screen. Both fixed; the view holds whatever world point
was centred rather than re-fitting, because docs/03 says reshuffling
destroys the spatial memory analysts build.

### Honest gaps across all of it

- **No adapters, no scheduler, no persona vault.** Capture is manual, which
  is deliberate (docs/14 C2) and means none of the persona-management risk
  exists yet -- but it also means nothing collects on its own.
- **The document bucket is normalise + dedupe only.** No versioning, no
  indexing, no embeddings, no watch matching, no parser health checks.
- **Phase 5 has only the egress gate.** No SMTP, no Jira, no webhooks, no
  notification centre, no digest or quiet hours.
- **Phase 6 has only merge.** No ACH matrix, no report builder, no
  retention/purge jobs, no WebAuthn, no break-glass. Merge itself lacks
  DUAL CONTROL -- one cleared analyst with a fresh second factor can merge
  alone -- and the case-owner notification docs/01 asks for is Phase 5.
- **Phases 7, 8, 9 untouched.** Phase 7 is decided (message-level capture,
  decision 35); Phase 8 is BLOCKED on the prohibited-content policy
  (decision 36, and the warning at the top of the README).
- **CI now runs four gates** (decision 42) and **rate limiting has landed**
  (decision 43). The security items still deferred are session IP/UA
  binding, a non-owner DB role, login timing equalisation and the
  compartment registry.
- **Analytics still run in-process** (decision 30). Fine at this scale, and
  no longer an unmetered DoS surface.

## What to do next

The enhancement map's **E-items are now the clear top of the list**, and E3
in particular has become cheap: retraction genuinely dissolves elements from
the graph as of this phase, so "retract a source and watch the network
fall apart" is one endpoint away from being the demo that sells the
assertion model.

1. **E1 — evidence at the point of claim.** Still the largest gap between
   the product as built and as pitched: the first real session produced
   fourteen assertions and zero exhibits.
2. **E3 — retraction in the UI.** `retract_assertion` exists in the service,
   is exercised by two Phase 3 tests, and is exposed nowhere.
3. **E4 — recovery codes.** A correctness gap against docs/05.
4. **U3 — `valid_from` / `valid_to` in the entity and relationship forms.**
   The scrubber and trust decay both work and both currently have almost
   nothing to chew on; `demo-network` sets these, the UI does not.
5. **U1 — sigma.js and ForceAtlas2.** The hand-rolled canvas will not hold
   at thousands of nodes, and Phase 3 makes larger graphs worth loading.

Then Phase 4 (collection) per docs/09 — but note its own warning: do not
switch on a firehose until the graph and assertion layer have been used in
anger on a real case for a week.
