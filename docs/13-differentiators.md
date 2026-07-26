# 13 — Differentiators

Everything in this scaffold that the commercial market handles badly or
not at all, consolidated. Scored honestly: several are cheap and decisive,
a few are expensive and worth it, one or two are expensive and optional.

**Market baseline for comparison:** Maltego, i2 Analyst's Notebook, SL
Crimewall, Palantir Gotham. All are strong at collection breadth and
visual link analysis. All are weak in the same three places: they treat
links as facts rather than graded claims, they conflate personas with
people, and their analytics stop at degree and betweenness.

---

## Tier 1 — Headline capabilities

Build these. They are the answer to "why not just buy Maltego?"

### 1. Signed trust networks and structural balance

Vouches, guarantors and escrow as `+1`. Rip reports, disputes and bans as
`−1`. Almost every tool stores only positive ties, which discards the most
diagnostic signal in a criminal marketplace.

With signs you get structural balance theory. **Unbalanced triads are
leads**: A vouches for B, B vouches for C, A accuses C. That configuration
is unstable and means one of three things — your data is wrong, a
relationship is about to break, or someone is running two personas. All
three are worth an analyst's attention, and the system can surface them
automatically.

*Cost: low. Payoff: high. Nothing else does this.*

### 2. Burt's constraint as a first-class metric

Structural holes theory identifies actors who span otherwise disconnected
clusters and profit from the gap. In cybercrime that is precisely the
initial access broker, the launderer, the escrow provider.

**Low constraint plus low degree is the broker signature** — few
connections, but the only ones bridging two worlds. That person is usually
more consequential and less replaceable than the loudest poster, and no
mainstream link-analysis tool exposes the metric.

*Cost: low — igraph computes it. Payoff: high.*

### 3. Key player analysis

*Which set of n actors, removed, maximally fragments this network?*

The question every disruption operation actually asks, and the one no
commercial tool answers. Critically, **the optimal removal set is usually
not the top-n individually central actors** — two high-betweenness nodes
often broker the same two clusters, so taking both is redundant.

Greedy seeding plus local search over the fragmentation objective finds
genuinely better answers, and the surprise is the value.

*Cost: medium. Payoff: very high. This is the demo that wins the room.*

### 4. Assertion layer with retraction propagation

Every edge traces to a graded, sourced, timestamped claim. Retract a
source and watch the network visibly change.

Competing products bake links in as facts. When a source turns out to be a
rip artist, they have no mechanism beyond hand-auditing hundreds of edges,
which nobody does, so the bad data stays.

*Cost: high — it shapes the whole schema. Payoff: very high. Impossible to
retrofit.*

### 5. Temporal replay with visible coverage gaps

The timeline scrubber: drag it and the graph plays through history. Edges
appear and grey out, groups fragment after an arrest, communities re-form.

The differentiating half is the **collection density strip** under the
scrubber. A quiet period on the graph might be inactivity or it might be
a broken parser and three weeks of missed collection. Every tool I know
of renders those identically. Showing the difference prevents a specific
and serious analytic error.

*Cost: medium, given bitemporal storage. Payoff: high.*

---

## Tier 2 — Structural advantages

Model decisions that make everything above possible. Individually
unglamorous, collectively the reason the product holds up.

### 6. Identity / Person separation

`IDENTITY` is what you observed. `PERSON` is who you assess them to be.
Joined by a confidence-scored, reversible edge. Collapse them and a wrong
attribution can never be cleanly unwound — every edge now points at the
wrong thing with no record of why.

### 7. Reversible merges

The losing node persists with `merged_into_id`; edges are repointed with
their original endpoints recorded. Merging is the operation most likely to
quietly corrupt a case, and in most tools it is irreversible.

### 8. Trust decay at projection time

A vouch from 2019 is not a vouch from last month. Apply a half-life when
building the projection rather than mutating stored weights, so the
underlying observation stays intact and the decay parameter stays
adjustable per case.

### 9. Machines propose, analysts dispose — with explanations

Extractors and inference jobs write proposals, never graph elements.
Every suggestion carries a plain-language reason: *"these two personas
posted within 90 seconds of each other in 14 threads across 3 forums."*

A bare 0.87 similarity score is either over-trusted or ignored. An
explanation can be argued with, which is the point.

### 10. Two-mode projection with Newman weighting

Actor × forum, actor × thread, actor × wallet. Divide by event size when
projecting or a 500-member forum manufactures a spurious clique.
Co-affiliation is how you find cells that never communicate directly on
the record. UCINET does this; the link-analysis tools mostly do not.

### 11. Structural equivalence and blockmodelling

Two actors who never interact but occupy the same structural position are
playing the same role. **This finds the replacement** — the second
launderer, the developer who took over. Available in UCINET, absent from
every investigative platform.

### 12. ACH built into the graph

Hypotheses and diagnosticity scoring in the same surface as the evidence.
Cybercrime attribution is where confirmation bias does the most damage; a
team eight months into one theory reads every new post as support. Putting
the competing hypothesis in the same view is a structural correction.

---

## Tier 3 — Craft details

Cheap, specific, and each one prevents a real and common error.

### 13. Tox nospam-invariant indexing

Index the first 64 hex of a Tox ID — the public key — not the full 76.
Users rotate nospam to shed contacts, which changes the ID string but not
the identity. Tools that key on the whole string silently lose the actor.

### 14. Telegram numeric ID over `@username`

Usernames are recycled after release; the numeric ID is durable. Analysts
get this wrong constantly and it produces confident, wrong attributions.

### 15. OMEMO device fingerprints as device selectors

Two different JIDs publishing the same OMEMO fingerprint is the same
physical device. Far stronger than a shared nickname, and almost never
collected. Model as a `DEVICE` node so it links personas without merging
them.

### 16. Contact-block parsing with role awareness

Co-declaration — an actor publishing several selectors together — is
strong identity evidence, because *they* are asserting the linkage. But
parse block structure, not loose selectors: contact blocks routinely
include the escrow's Jabber and the guarantor's Tox. Attributing those to
the vendor is an easy and serious error.

Paired with `CLAIMED` vs `CONFIRMED` control, so impersonation — scammers
copy vendors' contact blocks wholesale — is representable rather than
silently resolved the wrong way.

### 17. PM provenance classes

Whether a private message came from our persona being a party, a database
leak, a seizure, or voluntary disclosure changes its reliability *and* its
legal standing. Most tools store "we have the PMs" as one undifferentiated
state.

### 18. Quote and signature stripping before extraction

A quoted block attributes every address in it to whoever quoted it. A
signature puts the same Jabber ID on 4,000 posts as 4,000 observations.
This single omission pollutes a case faster than anything else, and it is
a few lines of parser work.

### 19. Fuzzy-hash sample clustering into the actor graph

`ssdeep`, `TLSH`, `imphash` and Rich header cluster samples by builder and
build environment. That cluster points at a **developer**, who is usually
a more interesting and less replaceable node than any affiliate. Sample
handling normally lives in a separate lab tool where this pivot is lost.

### 20. Exposure-aware external actions

Sandbox detonation and some enrichment lookups tell the provider — and
sometimes the world — what you are interested in. Operators watch public
sandboxes for their own samples. Mark providers with an exposure level and
say so in the confirmation dialogue, in plain words.

### 21. Watchlist-driven triage with near-duplicate suppression

A record matching a watched selector surfaces in seconds; a generic combo
list sinks silently. Minhash clustering stops the same leak post arriving
from nine feeds and burying the queue.

### 22. Single-source and stale-confidence flagging

Assertions resting on one source are marked as such — not wrong, but
visible. Confidence graded HIGH three years ago with no corroboration
since decays into a review prompt rather than sitting there looking solid.

### 23. Source diversity indicator

A network built entirely from one forum is a picture of that forum, not of
the ecosystem. Show it per case.

### 24. Hide-inferred, one key

Space bar temporarily removes every dashed edge. One key, instant answer
to *what do I actually know?* Analysts will use it constantly, and it costs
an afternoon.

---

## Tier 4 — Later, high value

- **Disclosure pack generator.** Given a case and a date range: every
  assertion with its provenance chain, evidence manifest with hashes, the
  access log, and retracted material with reasons. If cases ever reach
  court this becomes the highest-value feature in the product.
- **Change-point detection on network structure.** Sharp shifts in density
  or modularity usually mean an arrest, a dispute or an exit scam.
- **Cross-case pivoting with compartment respect.** "There is a match in a
  case you cannot see — request access from its owner." Enormously useful
  and a genuine compartment risk. Policy decision, see `docs/00` Q5.
- **Cyrillic homoglyph-aware handle matching.** Latin/Cyrillic lookalikes
  in handles are a real attribution problem in this specific domain.

---

## What to build first, if forced to choose

Signed edges (#1), Burt's constraint (#2), and the craft details in Tier 3
are all cheap. Together they would already make this more analytically
capable than most of the market.

The assertion layer (#4) is the expensive one and the one that cannot be
added later. Build it in Phase 1 or accept that it is never getting built.
