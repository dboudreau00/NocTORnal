# 15 — Handoff

Everything a fresh session needs to continue this build, written 2026-07-25
after Phases 0–2 shipped. Read this, then `CLAUDE.md`, then
`docs/14-enhancement-map.md`. Phase 3 starts at the bottom.

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
jeffreyturpine@gmail.com` — prints a URL that lands in the UI already
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

## Phase 3 — start here

Goal (docs/09): *the tool answers "who holds this network together" with
something better than degree count.*

Build in `apps/api/src/noctornal_api/` alongside `projections.py`, which
already provides the projected subgraph, the four presets, and the
clearance/compartment filtering every query must respect. **Reuse
`GraphService.project()`** — do not re-query the graph.

1. **Analytics worker with igraph.** docs/02 specifies igraph over NetworkX
   ("NetworkX dies around 50k edges"). Local metrics stay synchronous;
   betweenness, communities and key-player go to a queue (Redis and NATS are
   both already in the stack), writing to `analytics.metric_run` /
   `node_metric` / `community_assignment`, which exist unused since 0015.
   `metric_run` has `graph_hash` for cache-skip and `is_approximate` +
   `sample_size` because docs/03 insists the UI say when a number is sampled.
2. **Burt's constraint and effective size** — docs/03 calls it arguably the
   most useful metric here and docs/13 says almost nobody surfaces it. The
   data already shows a broker (`spectre_lynx`: degree 3, clustering 0.0).
3. **Betweenness**, with the UI teaching the low-degree/high-betweenness
   pattern rather than only printing a value.
4. **Leiden communities**, tinting the selected node's community.
5. **Signed structural balance** — unbalanced triads as leads. The signs are
   already stored and `spectre_lynx` is both vouched for and accused, which
   is exactly the shape.
6. **Key player (KPP-Neg)** with a fragmentation preview.
7. **Trust decay** at projection time (docs/03: half-life, default 12
   months) — never mutate the stored weight.

Non-negotiables while building it: metrics are computed **against a named
projection** and the parameters travel with every answer; inferred edges stay
out unless the projection opts in; every query filters by the caller's
clearance and compartments, and an edge appears only when **both** endpoints
are visible.

Before Phase 3, consider the enhancement map's E-items — evidence capture in
the UI and retraction — which are small and close the biggest gap between the
product as built and as pitched.
