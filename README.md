# NocTORnal

A HUMINT and social network analysis platform for cybercrime investigation.
Build the graph of actors, personas, groups and the trust relationships
between them, backed by evidence with a chain of custody, fed by monitored
forums and channels.

*(Named 2026-07-24; previously scaffolded under the codename "lattice".)*

## Read in this order

| | | |
|---|---|---|
| **[QUICKSTART.md](QUICKSTART.md)** | Start it and log in — one command, then create your account | **Run it** |
| **[GETTING-STARTED.md](GETTING-STARTED.md)** | Blocking decisions, day-one setup, first four Claude Code sessions | **Read first** |
| **[CLAUDE.md](CLAUDE.md)** | Working agreement and the twelve non-negotiable invariants | Read second |
| [docs/00-decisions.md](docs/00-decisions.md) | Decisions taken, and **ten open questions for you** | |
| [docs/01-domain-model.md](docs/01-domain-model.md) | Identity vs person, assertions, signed edges, temporality | The core |
| [docs/02-architecture.md](docs/02-architecture.md) | Zones, stack and the reasoning behind each choice | |
| [docs/03-graph-analytics.md](docs/03-graph-analytics.md) | The UCINET-grade metric catalogue | |
| [docs/04-collection.md](docs/04-collection.md) | Adapters, personas, the aggregation bucket | |
| [docs/05-security-rbac.md](docs/05-security-rbac.md) | RBAC + ABAC, MFA, hardening | |
| [docs/06-interface.md](docs/06-interface.md) | Dark UI tokens and the sociogram interaction model | |
| [docs/07-integrations.md](docs/07-integrations.md) | SMTP, Jira, webhooks — and what must never sync | |
| [docs/08-governance.md](docs/08-governance.md) | TLP, retention, tradecraft, defensibility | |
| [docs/09-roadmap.md](docs/09-roadmap.md) | Twelve weeks, phased, with Claude Code prompt shapes | |
| **[docs/13-differentiators.md](docs/13-differentiators.md)** | **Every edge over the market, tiered by payoff vs cost** | **Start here if you want the pitch** |
| **[docs/14-enhancement-map.md](docs/14-enhancement-map.md)** | **What the first real session revealed, and what to build next, by payoff** | **Read after using it** |
| [db/schema.sql](db/schema.sql) | Full DDL — the densest artefact here | |
| [db/seed_ontology.sql](db/seed_ontology.sql) | Node, edge and selector vocabularies | |

### Concept layer — designed, not decided

Sketches. Each ends with open questions that need a human answer before
Claude Code implements anything. Draft tables live in
[db/schema_concept.sql](db/schema_concept.sql), kept separate so the
difference between *decided* and *sketched* stays visible.

| | |
|---|---|
| [docs/10-comms-channels.md](docs/10-comms-channels.md) | Session, Tox, XMPP, Wire, Matrix, forum PMs. Contact-block parsing and the selector traps |
| [docs/11-malware-handling.md](docs/11-malware-handling.md) | Sample intake, containment, the RE handoff channel |
| [docs/12-ingest-api.md](docs/12-ingest-api.md) | `sk_` keys, feed parsing, auto-categorisation, triage scoring |

## The three ideas everything else follows from

**A handle is not a person.** `IDENTITY` (what you observed) and `PERSON`
(who you assess them to be) are separate node types joined by a
confidence-scored, reversible edge. The entire discipline of attribution
lives in that gap, and collapsing it into one record means you can never
cleanly unwind a wrong call.

**Nothing is a fact.** Every attribute and every edge traces to an
assertion carrying a source, an Admiralty grading, a rationale and two
timestamps. The graph you see is a projection of current, non-retracted
assertions. Retract a source and watch the network change.

**Machines propose, analysts dispose.** Extractors and inference jobs write
proposals, never graph elements. Inferred edges render dashed and sit
outside the metrics until a human accepts them. A graph that invents links
is worse than no graph, because it looks authoritative.

## Three things worth building that the market does badly

- **Signed trust networks with structural balance.** Vouches and rip
  reports as positive and negative edges. Unbalanced triads are leads.
- **Burt's constraint as a first-class metric.** Low constraint is the
  broker signature — the access broker, the launderer, the escrow. Almost
  no link-analysis tool surfaces it.
- **Key player analysis.** *Which set of n actors, removed, maximally
  fragments this network?* The answer is usually not the top-n most
  central individuals, and that surprise is the value.

## Where to start

To **run it**: [QUICKSTART.md](QUICKSTART.md) — one command to start the
stack and the UI, one more to create your account.

To **understand the decisions**: [GETTING-STARTED.md](GETTING-STARTED.md)
and [docs/00-decisions.md](docs/00-decisions.md).

## State of the build

Phases 0, 1 and 2 are implemented and running, not just designed:

- Postgres schema owned by an Alembic chain (0001–0025) that round-trips
  from base to head; the ontology is generated from one definition.
- Authentication (Argon2id + replay-protected TOTP + server-side sessions),
  and the five-part access gate as a single evaluator every endpoint calls.
- The assertion layer, enforced **in the database**: no node or edge can be
  committed without a supporting assertion (invariant 1).
- Evidence with WORM object-lock storage, dual hashing, and an append-only,
  hash-chained chain of custody.
- Cases, selectors with per-type normalisers, tags, node sets, full-text
  search, and a REST API.
- The sociogram: four projection presets, ego networks, shortest paths, a
  timeline scrubber over `as_of`, local metrics (degree, weighted, signed,
  clustering, k-core), saved layouts, and the inspector that answers
  "why do we believe this" with the Admiralty grading behind every claim.

254 tests cover it, the Postgres and MinIO legs env-gated.

**Not built yet:** Phase 3 analytics — betweenness, Burt's constraint,
communities, key-player — which need igraph in a worker; and Phases 4–9,
collection through ingest. Read
[docs/14-enhancement-map.md](docs/14-enhancement-map.md) for what a real
session showed is most worth doing next (evidence capture in the UI leads).
`docs/00-decisions.md` records every decision and open question, and
`QUICKSTART.md` ends with an honest list of what this deployment is *not*
hardened for.
