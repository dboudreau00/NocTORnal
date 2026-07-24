# 02 — Architecture

## Topology

Three trust zones. The separation is the point: a burnt collection persona
must not be a route into the case data.

```
┌─ ZONE C: COLLECTION ────────────────────────────────────────────┐
│  collector workers ──> egress proxies ──> forums / Telegram     │
│  (holds decrypted persona credentials)                          │
│  NO database credentials. NO inbound access.                    │
│  Publishes captured items onto the queue. One direction only.   │
└──────────────────────────┬──────────────────────────────────────┘
                           │  message queue (NATS / Redis Streams)
┌──────────────────────────▼──────────────────────────────────────┐
│  ZONE B: PROCESSING                                             │
│  normaliser → dedupe → extractor → watch matcher → proposal gen │
│  analytics workers (igraph)  •  notifier (SMTP / Jira / webhook)│
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  ZONE A: CORE                                                   │
│  FastAPI  •  Postgres 16 + pgvector  •  Redis  •  MinIO (WORM)  │
│  OpenFGA  •  Next.js front end                                  │
└─────────────────────────────────────────────────────────────────┘
```

Collectors never touch Postgres. If a collection host is compromised the
attacker gets persona credentials and a write-only queue topic — bad, but
recoverable. If collectors held DB credentials, a compromise would be the
whole case file.

## Stack, with reasoning

**Postgres as the system of record, not a graph database.**
The tempting move is Neo4j. Resist it for the system of record. Your data
is deeply relational (assertions, custody, RBAC, bitemporal history) and
Postgres handles that far better. Below roughly 10M nodes — which no
single case will approach — graph traversal is not the bottleneck; the
analytics are, and those want the whole graph in memory anyway.

Pattern: Postgres holds truth → an analytics worker materialises a
projection into an in-memory `igraph` → results cached in Redis and
persisted to `analytics.node_metric`. If you later want Cypher for
exploratory querying, add Memgraph as a read replica of the projection.
Do not make it authoritative.

**`igraph`, not NetworkX.** NetworkX is pure Python and will fall over
around 50k edges when you ask for betweenness. `igraph` has a C core and is
an order of magnitude faster. `graph-tool` is faster still but is a
packaging ordeal. Start with `igraph`.

**FastAPI / Python.** The gravity is overwhelming here: `igraph`,
`telethon`, `scikit-learn`, `spacy`, the whole extraction ecosystem. A
TypeScript backend means a second Python service anyway.

**sigma.js + graphology for the sociogram.** WebGL, comfortable at 50–100k
nodes. Cytoscape.js is nicer for rich interaction on small graphs — use it
for the focused "ego network of one actor" view if you want, but the main
canvas needs WebGL. D3 force layout will not survive contact with a real
case.

**OpenFGA or SpiceDB for authorisation.** Your access model is
relationship-shaped — *this user can read this evidence because they are
assigned to the case that owns it, and their clearance is at or above its
TLP*. Zanzibar-style systems express that directly. Hand-rolling it
produces authorisation logic scattered across forty endpoints, which is
how access-control bugs happen.

**MinIO with object lock** for evidence. S3-compatible, self-hostable, and
object lock gives real WORM semantics for chain of custody.

## Realtime sociogram — the honest engineering picture

"Realtime" needs unpacking, because betweenness centrality on a graph of
any size is not a realtime operation.

Three tiers, and the UI must be explicit about which one a number came
from:

| Tier | Latency | What it covers |
|---|---|---|
| **Immediate** | < 100 ms | Node/edge added, removed, moved. Pushed over WebSocket, applied to the client graph, layout locally relaxed. Degree updates incrementally. |
| **Fast** | 1–5 s | Local metrics: degree, clustering coefficient, k-core, ego density. Recomputed on the changed neighbourhood. |
| **Batch** | 10 s – 5 min | Global metrics: betweenness, closeness, eigenvector, Louvain communities, key-player sets, structural holes. Debounced, queued, cached against a graph hash. |

Implementation notes:

- **Debounce and coalesce.** Bulk ingest generates thousands of changes.
  Collapse them into one metric run per projection per window.
- **Graph hash as cache key.** Hash the sorted edge list of the projection.
  Unchanged hash → serve cached metrics, skip the run entirely.
- **Approximate betweenness.** Brandes with pivot sampling gets you within
  a few percent at a fraction of the cost. Store `is_approximate = true`
  and show it in the UI. Analysts will make removal decisions from these
  numbers; they are entitled to know the error bars exist.
- **Never block a write on a metric run.** The graph edit commits; metrics
  catch up and the UI shows a subtle staleness indicator.

## Data flow: capture to graph

```
watch fires
  → collection_run (which persona, which egress, which parser version)
  → raw HTML/JSON to MinIO (WORM, sha256 recorded)
  → document row: normalised text + hash + embedding   ← THE BUCKET
  → dedupe on content_sha256 (edited posts version, not duplicate)
  → extractors → extraction rows (selectors with offsets)
  → watch matcher → watch_hit → notification (deduped, digested)
  → proposal generator → proposal rows          ← STOPS HERE
  → ─────── human review ───────
  → accepted proposal → node / edge / assertion
```

The stop before the graph is deliberate and load-bearing. Auto-ingestion
into the graph produces a network that looks impressive and means nothing,
because it is mostly forum boilerplate, quoted text and signature blocks.

## Repository layout

```
noctornal/
├── apps/
│   ├── api/              FastAPI: routers, services, repositories
│   ├── web/              Next.js
│   ├── collector/        source adapters, scheduler, persona manager
│   ├── processor/        normalise, extract, match, propose
│   └── analytics/        igraph projections and metrics
├── packages/
│   ├── ontology/         node/edge/selector types, shared TS + Py codegen
│   ├── authz/            OpenFGA model + policy helpers
│   └── crypto/           envelope encryption, hashing, audit chain
├── db/                   schema, migrations, seeds
├── docs/
└── infra/                compose, k8s, terraform
```

The `ontology` package generating both TypeScript and Python types from one
source is worth the setup cost — the alternative is edge-type strings
drifting between front end and back end, and silent data corruption.

## Deployment posture

Single-tenant, self-hosted, air-gappable. The schema carries no `tenant_id`
because multi-tenancy on this data class is a liability rather than a
feature — deploy a second instance instead. Compose for development, k8s
with network policies enforcing the zone boundaries for production.
