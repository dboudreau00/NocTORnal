# 09. The phases

The build was sequenced into ten phases, 0 through 9, each independently
useful. All ten are built; `ROADMAP-REMAINING.md` holds what is left of each
and is the only place completion is worked out.

This file is what each phase was FOR, and the exit criterion it was held to.
The code cites it by phase number for that reason. It carried a checkbox list
until 2026-09-15; the boxes had stopped being maintained around Phase 3 and
were wrong in both directions, which is worse than being out of date, so they
are gone rather than corrected. What is true now is not a checkbox question.

## The one ordering constraint that matters

**The graph and assertion layer must work end to end before collection is
switched on.** Pointing a firehose at a half-built model produces a landfill
you then have to clean by hand. So Phase 1 (the assertion layer, invariant 1)
and Phase 2's projection had to be right before Phases 4 and 9 fed proposals
into them: `proposals.py` accepts through `GraphWriteService`, so an accepted
proposal is born as a real inferred assertion and a defect in the model
becomes a defect in every collected edge.

The plan went further and said to stop after Phase 1 and use the tool on a
real case for a week before building anything else, because everything
downstream assumes the model is correct. Two other dependencies are real:
analytics (3) can only measure a graph that exists, and the egress gate (5)
had to exist before comms (7) captured message content it could leak.

## The ten

| Phase | For | Done when |
|---|---|---|
| **0. Foundation** | The monorepo, Compose, Alembic, the ontology package, password and TOTP auth, the access gate as one function, the hash-chained audit log, CI | A user can register, enrol TOTP, sign in, and every action appears in a **verifiable** audit chain. The word verifiable is the load-bearing one: the chain was written for weeks before anything recomputed it |
| **1. Graph core** | Nodes, edges, the assertion layer, selectors, evidence with WORM and custody, cases as the unit of access | An analyst can build a case entirely by hand, and every edge answers "why do we believe this?" in one click |
| **2. Sociogram** | Projection presets, the graph API (neighbourhood, path, subgraph, as-of), the canvas renderer, the inspector, live local metrics | A 2,000-node case renders at 60fps and an analyst can find a broker visually |
| **3. Analytics** | igraph and leidenalg: betweenness, brokerage, k-core, communities, Burt's constraint, key player, signed balance | The tool answers "who holds this network together" with something better than a degree count. Met on the demo network: the optimal three-actor removal set fragments it to F=0.727, where the top three by betweenness leave it in one piece |
| **4. Collection** | The adapter interface, the persona vault, the document bucket, watch matching, the proposal review gate | A watch on a real forum fills the bucket for a week without silent breakage, and triage is a pleasant hour rather than a grim one |
| **5. Notification and integration** | The egress gate every outbound path calls, the notification centre, delivery preferences, the delivery ledger | A priority-1 watch hit reaches the right analyst, and nothing leaves the building that the classification forbids |
| **6. Tradecraft and hardening** | Entity-resolution merge with an exact reversal, four-eyes approval, break-glass, retention and purge, the assumptions register | The irreversible operations take two humans, the emergency path is loud rather than hard, and every assumption a case rests on is written down |
| **7. Comms channels** | The durable-selector mapping, the contact-block parser, bindings at three verification levels, PGP verification, co-participation | An identifier is indexed by what is durable about it, and a claim is never stored as a confirmation |
| **8. Sample handling** | The malware lab: quarantine, per-sample encryption, the origin split, triage gaps, detonation records | A reverse engineer can fetch a sample without the analyst session ever touching hostile bytes. **And not before docs/16 L1 is settled** |
| **9. Ingest API** | Write-only keys, raw-before-parse object storage, the dead-letter queue, category classification, the stealer-log compartment | A partner feed lands, what will not parse is visible rather than dropped, and a leaked key means junk data and never the case file |

## Later

Deliberately unscheduled, in no order: link prediction and stylometry
(hypotheses only), a disclosure-pack generator, STIX and MISP export,
cross-case pivoting that respects compartments, blockchain analytics,
translation for non-English sources, a mobile read-only view, CONCOR
blockmodelling, change-point detection on network structure.
