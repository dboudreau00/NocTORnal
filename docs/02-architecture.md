# 02 — Architecture

> **Rewritten 2026-09-09.** The first version of this document (2026-07)
> was the design sketch: three network trust zones, a message queue, an
> external authorisation engine, a JavaScript-framework front end and a
> GPU-rendered sociogram. None of it was built — the tree went a different
> way in its first week — and the sketch stayed here describing a program
> that did not exist while `ARCHITECTURE.md` described the one that did.
> An external review of Alpha 4 found the two disagreeing on every point it
> checked. This is now a description of what is in the tree. The reasoning
> that survived is kept; what was superseded is named as such in the last
> section rather than deleted, because `docs/00` records those decisions
> and a decision record should not lose its history.

## Topology

One process. `noctornal_api.http.app:app` — FastAPI under uvicorn — serves
the REST API under `/api/v1`, the analyst console under `/ui` and the
`/api/v1/live` WebSocket, and runs the collectors, the analytics and the
notification drain in-process. It talks to four services.

```
┌─ API PROCESS  (noctornal_api, one uvicorn) ─────────────────────────────┐
│  /ui          static console: HTML/CSS/JS, no build step, strict CSP    │
│  /api/v1      routers ──► five-part access gate ──► services            │
│  /api/v1/live WebSocket fed by Postgres LISTEN/NOTIFY (one listener)    │
│  collection   adapters + PersonaVault, run by call (no scheduler loop)  │
│  analytics    igraph, synchronous on request (decision 30)              │
│  notify       dispatch_due(), called — not a worker (decision 46)       │
└────────┬────────────────┬─────────────────┬──────────────────┬──────────┘
         │                │                 │                  │
   Postgres 16         Redis 7           MinIO            Mailpit (dev)
   + pgvector          rate-limit       object lock       SMTP sink
   10 schemas,         meter (GCRA      evidence / raw /
   58 revisions        in Lua), cache   samples buckets
```

**There is no separate collection zone.** The 2026-07 sketch put the
collectors in their own network segment, holding persona credentials and
no database credentials, so that a burnt persona could not become a route
into the case file. That separation is not in the tree: `PersonaVault`
lives in `apps/api/src/noctornal_api/collection.py`, inside the process
that holds `DATABASE_URL` and `NOCTORNAL_TOTP_KEK`. What IS true — and what
invariant 7 says since 2026-09-09:

- persona credentials are envelope-encrypted at rest (AES-256-GCM, the
  same scheme as TOTP secrets — `security/envelope.py`) and decrypted only
  inside `PersonaVault.use()`, a context manager that yields the plaintext
  to one block, drops it and audits the use; there is no `get_secret()`;
- adapter errors are `redact()`-ed before they are stored, because a
  persona password lands in an HTTP error body more often than anyone
  expects;
- **a compromised API host is a compromised vault.** The shape of the code
  stops a credential reaching a response, a log or a traceback. It does
  not stop an attacker who is on the host, and nothing here claims it
  does.

Splitting a collector out — its own process, a queue between it and the
API, no database credentials — is a deliberate not-yet. The seam is real
(`Adapter` returns `Item`s, never graph elements, and
`CollectionService.run_once` is its only caller), but `RssAdapter` is the
only adapter, and the Telegram and forum adapters that would justify the
split are behind docs/16 L3 (authority to operate a persona at all) before
they are behind any topology question. When the split happens, decision 9
becomes true; until then `docs/00` records it as superseded.

## Stack, with reasoning

**Postgres as the system of record, not a graph database.**
The tempting move is Neo4j. Resist it for the system of record. The data
is deeply relational (assertions, custody, RBAC, bitemporal history) and
Postgres handles that far better. Below roughly 10M nodes — which no
single case will approach — graph traversal is not the bottleneck; the
analytics are, and those want the whole graph in memory anyway.

Pattern, as built: Postgres holds truth → `GraphService.project()`
materialises a projection into an in-memory `igraph` graph, filtered by
the caller's clearance and compartments in SQL → results are persisted to
`analytics.metric_run` / `node_metric` and cached against a hash of the
caller-visible graph AND the caller's visibility (decision 31), so a run
over RED nodes is never served to an AMBER analyst. If Cypher for
exploratory querying is ever wanted, add a graph store as a read replica
of the projection; do not make it authoritative.

**`igraph`, not NetworkX.** NetworkX is pure Python and will fall over
around 50k edges when you ask for betweenness. `igraph` has a C core and is
an order of magnitude faster. `graph-tool` is faster still but is a
packaging ordeal. `leidenalg` for communities — Leiden, not Louvain,
because Louvain can produce internally disconnected communities.

**FastAPI / Python.** The gravity is overwhelming here: `igraph`,
`telethon`, `scikit-learn`, `spacy`, the whole extraction ecosystem. A
TypeScript backend means a second Python service anyway. One process,
because at this scale a worker adds a process, a client dependency, a
progress UI and a new failure mode without changing a single number
(decision 30); the compute is written worker-ready — `analytics.py` is
pure and database-free — so a worker later is a change of caller, not of
algorithm.

**A vanilla HTML/CSS/JS console under a strict CSP.** Seven static files in
`apps/api/src/noctornal_api/http/static/` — `index.html`, `app.js`,
`app.css`, `theme.css`, `layout-worker.js`, two SVGs — served same-origin
under `script-src 'self'` with no inline script, no bundler and no CDN. The
sociogram is a Canvas 2D renderer: a main-thread spring loop for
interactive drag, and a hand-written ForceAtlas2 with Barnes-Hut repulsion
in a Web Worker (`layout-worker.js`; decision 37 measured 400 nodes / 1,187
edges in about a second off-thread). No npm dependency, because under this
CSP an npm dependency means adopting a build step, and that is a real
decision that should not arrive as a side effect of wanting a layout
(docs/14 U1). The cost is the ceiling: Canvas 2D is comfortable at hundreds
of nodes and thousands of edges, not at the 50–100k a GPU-backed renderer
reaches — which is above the case sizes `docs/00` open question 3 expects,
and is the decision to reopen if that changes.

**One five-part access gate, answered from Postgres.**
`security/access.py::evaluate` runs verb, assignment, clearance lattice,
compartment subset and step-up freshness with no short-circuit, and every
case-scoped router depends on it through `require()`, `require_global()`
or `require_step_up` in `http/deps.py`. The inputs come from `iam.*` via
`PgAccessResolver`; the relationship-shaped part of the model — *you may
read this because you are assigned to the case that owns it* — is the
assignment leg, one join. No external authorisation engine is involved
(see the last section). `docs/05` warned that hand-rolling scatters the
logic across forty endpoints; the warning is honoured by having one
function, one resolver, and a fail-closed `AccessResolutionError` for
anything unresolvable.

**MinIO with object lock** for evidence. S3-compatible, self-hostable, and
object lock gives real WORM semantics for chain of custody — COMPLIANCE
mode, not GOVERNANCE, so not even the API's own credentials can delete
before retention expires (decision 26). Three buckets: evidence (locked),
raw ingest bytes (`rawstore.py`, persisted before any parser runs), and
samples (never locked, because rejection must be able to destroy bytes).

**Redis** for the rate-limit meter — GCRA in one Lua script, so several
API processes share one clock and one decision (decision 43) — and cache.
Without `REDIS_URL` the limiter runs per-process and says so at startup.

**Mailpit** as the development SMTP sink; a real deployment points
`SMTP_HOST` at a relay, behind the same TLP egress gate as every other
outbound path (invariant 8).

## Realtime sociogram — the honest engineering picture

"Realtime" needs unpacking, because betweenness centrality on a graph of
any size is not a realtime operation.

Three tiers, and the UI is explicit about which one a number came from:

| Tier | Latency | What it covers |
|---|---|---|
| **Immediate** | < 100 ms | Node/edge added, removed, moved. Pushed over the `/api/v1/live` WebSocket (Postgres `LISTEN`/`NOTIFY`, one listener per process; the socket carries ids, never case content), applied to the client graph, layout locally relaxed. |
| **Fast** | 1–5 s | Local metrics: degree, weighted and signed degree, clustering coefficient, k-core, density, evidence coverage. `GraphService.metrics()`, in Python, synchronous — cheap under 5k nodes. |
| **Batch** | seconds | Global metrics: betweenness, harmonic closeness, eigenvector, Leiden communities, key-player sets, Burt's constraint, structural balance. Run synchronously in the API process on request (decision 30), cached against a hash of the caller-visible graph and the caller's visibility (decision 31). |

Implementation notes:

- **Graph hash as cache key.** The hash is over the sorted caller-visible
  node and edge lists. Unchanged hash → the cached run is served.
- **Approximate betweenness.** Above 3,000 nodes the run switches to
  Brandes with pivot sampling (512 pivots) and stores `is_approximate =
  true` with the sample size; the UI shows it. Analysts make removal
  decisions from these numbers; they are entitled to know the error bars
  exist.
- **Caps, not queues.** Key-player search refuses above 5,000 nodes or on a
  truncated projection; the triad census stops at 2,000. The band docs/03
  marks synchronous is enforced by refusing, not by backgrounding.
- **Never block a write on a metric run.** The graph edit commits; metrics
  are recomputed on the next request and the UI shows what projection and
  parameters a number came from.

## Data flow: capture to graph

```
watch fires / run_once called
  → collection_run (which persona, which egress profile, parser version)
  → document row: normalised text + content_sha256, versioned on edit
    (`supersedes_id`); the `embedding` column exists and nothing fills it yet
  → dedupe on content_sha256 (an edited post is a version, not a duplicate)
  → extractors → extraction rows (selectors with character offsets)
  → watch matcher → watch_hit → notification (deduped, digested, TLP-gated)
  → proposal generator → proposal rows          ← STOPS HERE
  → ─────── human review ───────
  → accepted proposal → node / edge / assertion, born is_inferred
```

The ingest API (Phase 9) is the other way in: `POST /ingest` with a
write-only key persists the raw bytes to the `noctornal-raw` bucket and an
`ingest.batch` row and returns 202 BEFORE any parser runs, so a wrong
parser is replayable; anything that will not parse lands in
`ingest.dead_letter` with the fragment (invariant 12), and what does parse
feeds the same proposal path.

The stop before the graph is deliberate and load-bearing. Auto-ingestion
into the graph produces a network that looks impressive and means nothing,
because it is mostly forum boilerplate, quoted text and signature blocks.
`ProposalStore` holds no `GraphWriteService` and physically cannot reach
`core.node` or `core.edge` (decision 39).

## Repository layout

```
noctornal/
├── apps/
│   └── api/               the ONE service: src/noctornal_api/
│                            http/        app factory, routers, deps, static/ console
│                            security/    access gate, envelope, passwords, TOTP, sessions
│                            *.py         graph, projections, analytics, evidence, samples,
│                                         ingest, collection, comms, curation, reports ...
│                          tests/        the api pytest root
├── packages/
│   └── ontology/          node/edge/selector types; generates the SQL seed and TS
│                          types; the ONE source of selector normalisers; its own tests/
├── db/                    migrations/ (Alembic, authoritative), schema.sql (generated
│                          mirror), init/ (extensions only), concept/ (sketches)
├── scripts/               launch, bootstrap, demo seeds, dump_schema, source hygiene
├── infra/                 docker-compose.yml — the development stack
├── release/               packaged-release documents and installers
├── yara/                  fetched-never-bundled detection corpus (scripts/yara_db.py)
└── docs/
```

The sketch's `apps/web`, `apps/collector`, `apps/processor`,
`apps/analytics`, `packages/authz` and `packages/crypto` were never
created; everything they were to hold lives in the API package. The
`ontology` package generating both TypeScript and Python types from one
source is still worth its setup cost — the alternative is edge-type
strings drifting between front end and back end, and silent data
corruption — and CI fails if the generated files drift from the definition.

## Deployment posture

Single-tenant, self-hosted, air-gappable. The schema carries no
`tenant_id` because multi-tenancy on this data class is a liability rather
than a feature — deploy a second instance instead. Compose is the
development stack and the only deployment description in the tree; there
is no production manifest, and there is no network zone to enforce until
the collector split above happens. The gap between this and a defensible
deployment is written down rather than hidden: `QUICKSTART.md` ("Before
anything real") and `docs/17` list it — TLS termination, a database role
that does not own the tables, row-level security, session binding.

## Superseded from the 2026-07 sketch (recorded, not deleted)

Each row names what the sketch said, what shipped instead, and where the
decision lives. The names in the first column are the ones
`test_doc_invariants.py` refuses to see in a live description.

| Sketch (2026-07) | What is in the tree | Where recorded |
|---|---|---|
| Three trust zones; collectors with persona credentials and no database access | One process; `PersonaVault` inside the API; invariant 7 reworded | decision 9 — superseded note, 2026-09-09 |
| A NATS / Redis Streams queue between zones | No queue; `due_sources` / `run_once` are called | NATS removed from compose 2026-07-26 (R13) |
| Arq or Celery workers for collection and analytics | No worker; analytics synchronous, notifications by `dispatch_due()` | decision 30 (Arq/NATS marked removed there), decision 46 |
| OpenFGA or SpiceDB for authorisation | The five-part gate in `security/access.py` over `iam.*` | decision 8 superseded; OpenFGA removed from compose 2026-07-26 (R13) |
| Next.js 15 / TypeScript / Tailwind front end | Vanilla HTML/CSS/JS, no build step — superseded before a line was written | decision 37, docs/14 U1 |
| sigma.js + graphology (WebGL) sociogram | Canvas 2D + Barnes-Hut worker; sigma.js is not in the tree and never was | decision 37, docs/09 Phase 2 |
| UUIDv7 app-side ids | `uuid4()` app-side, `gen_random_uuid()` in the database; `pg_uuidv7` not installed — superseded 2026-09-09 | `CONVENTIONS.md` |
| `apps/web`, `apps/collector`, `apps/processor`, `apps/analytics`, `packages/authz`, `packages/crypto` | Never created | this document |
