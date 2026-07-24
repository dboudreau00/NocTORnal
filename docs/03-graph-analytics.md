# 03 — Graph analytics

You named UCINET, which tells me you want real social network analysis, not
a diagram with pretty edges. This is the section that separates the two.

## Projections first

**No metric is ever computed against "the graph."** It is computed against a
named `projection`: a filtered, parameterised view. Change the filter and
every number changes, so the parameters must be stored with the results or
the numbers are not reproducible.

A projection pins:

- which edge types count (`is_social_tie = true` by default — `SAME_AS` and
  `CONTROLS` are identity plumbing and will wreck centrality if included)
- whether inferred edges are in (default: no)
- minimum confidence
- time window (`as_of_from` / `as_of_to`)
- directed or symmetrised
- whether to project bipartite affiliations to one-mode

Ship four presets: **Communication**, **Trust**, **Financial**, **All ties**.
Analysts should be able to see instantly that the leadership picture is
different in each — because it genuinely is, and that difference is a
finding.

## Metric catalogue

### Centrality — "who matters", four different answers

| Metric | Reads as | Use when |
|---|---|---|
| Degree | Activity, visibility | Fast triage. Beware: loud ≠ important |
| Betweenness | Brokerage, control of flow | Finding the person whose removal fragments the network |
| Closeness | Reach, speed of access | Who can mobilise the network quickly |
| Eigenvector / Katz | Embeddedness among the important | Who has quiet influence without volume |

The pattern worth teaching in the UI: **high betweenness with low degree is
the classic broker signature**. Few connections, but they are the only
connections between clusters. In criminal networks that person is usually
far more consequential than the loudest poster, and is often the one the
group cannot replace.

For directed trust graphs also compute **in-degree of positive edges**
(received vouches = accumulated reputation) separately from out-degree
(vouches given = reputation staked). They mean opposite things.

### Structural holes — Burt

- **Effective size**, **efficiency**, **constraint**, **hierarchy**

Low constraint means an actor spans otherwise disconnected groups and
profits from the gap. In this domain that is the initial access broker, the
launderer, the escrow provider — the people who monetise being the bridge.
Burt's constraint is arguably the single most useful metric for cybercrime
network analysis and almost no commercial link-analysis tool exposes it.
Exposing it well is a differentiator.

### Cohesion and subgroups

- **Components**, weak and strong
- **k-core decomposition** — peels the periphery, exposes the durable core
- **Louvain / Leiden community detection** — prefer Leiden; Louvain can
  produce internally disconnected communities
- **Clique enumeration** and **n-clique**
- **Cohesive blocking** (Moody–White) — nested connectivity, expensive but
  excellent at surfacing an inner circle
- **Cut vertices and bridges** — articulation points are single points of
  failure in the network's structure

### Key player problem — Borgatti

This is the question law enforcement actually asks, and most tools cannot
answer it: *which set of n actors, if removed, maximally fragments this
network?*

- **KPP-Neg**: the removal set that maximises fragmentation `F`
- **KPP-Pos**: the smallest set that reaches the most of the network

Note the important part: **the optimal removal set is usually not the top-n
individually-central actors.** Two high-betweenness nodes often broker the
same two clusters, so removing both is redundant. Greedy or simulated
annealing over the fragmentation objective finds genuinely different, and
better, answers. Build this — it is a headline capability.

Implement as: greedy seed → local search, report `F` before and after,
render the fragments the removal would produce. Cap `n` and graph size, run
it as a batch job with progress.

### Signed-network analysis

Because trust edges carry `sign`:

- **Structural balance**: proportion of balanced vs unbalanced triads
- **Unbalanced triad enumeration** — surface these as leads. A vouches for
  B, B vouches for C, A accuses C is an unstable configuration: either the
  data is wrong, a relationship is breaking, or one of them is running two
  personas.
- **Status theory** on directed vouches — vouching upward is the norm; a
  respected actor vouching for a newcomer is a strong signal of a real
  relationship
- **Trust decay**: apply a half-life at projection time. Default 12 months,
  configurable per case. Never mutate the stored weight.

### Two-mode (affiliation)

Actor × forum, actor × thread, actor × wallet, actor × campaign.

- Bipartite projection to one-mode with **Newman weighting** (dividing by
  event size), otherwise a 500-member forum creates a spurious clique
- **Correspondence analysis** for two-mode positioning
- Co-affiliation is how you find cells that never communicate directly on
  the record

### Structural equivalence and roles

- **CONCOR** and **blockmodelling**
- **Regular equivalence** (REGE)

Two actors who never interact but occupy the same structural position —
same pattern of ties to the same kinds of others — are playing the same
role. This finds the *second* money launderer, the *replacement* developer.
Genuinely powerful and rarely available outside UCINET.

### Temporal

- Metric time series per node — a rising betweenness trend is a promotion
- **Change point detection** on network density and modularity — a
  fragmentation event is usually an arrest, a dispute or an exit scam
- Edge activation animation over the case timeline

### Link prediction (hypotheses only)

- Adamic–Adar, Jaccard, preferential attachment
- Shared infrastructure and shared selector co-occurrence
- Temporal co-presence (posting within N minutes across venues, repeatedly)
- Stylometric similarity

**All output is `proposal` rows or `is_inferred` edges. Never asserted
edges.** Each prediction carries a plain-language explanation of the signal.
"Suggested because these two personas posted within 90 seconds of each
other in 14 separate threads across 3 forums" is useful. A bare 0.87
similarity score is not, and will be either over-trusted or ignored.

## Performance

| Graph size | Approach |
|---|---|
| < 5k nodes | Exact, everything, synchronous, sub-second |
| 5k – 50k | Exact except betweenness (sampled); batch queue |
| 50k – 500k | Sampled centrality, Leiden with resolution tuning, server-side layout |
| > 500k | Filter first. A 500k-node sociogram is not a visualisation, it is a hairball. Force analysts through a projection. |

Layout: ForceAtlas2 with Barnes–Hut in a worker, seeded from stored
`layout_position` so the picture is stable between sessions. Analysts build
a spatial memory of their network — reshuffling it on every load destroys
real analytic value. Pinned nodes stay pinned.

## Presenting numbers honestly

- Always show rank and percentile alongside raw value. Betweenness of
  0.0341 means nothing to anyone; "3rd of 214" does.
- Flag approximation explicitly in the UI.
- Show the projection parameters next to the results, always.
- Warn when the graph has changed materially since the metrics were
  computed.
- Never present a single "importance score." Composite scores hide which
  structural property is driving them, and analysts will act on them
  without knowing what they mean.
