# 01 — Domain model

The model is the product. Everything else is plumbing around it.

## The central problem

You asked for "profiles for crime groups and sub-profiles for actors."
That framing is the natural one, and it is a trap. It assumes a stable
hierarchy — group contains actors, actors are people — and cybercrime
networks are not built that way. Three things break the naive model
immediately:

**A handle is not a person.** You observe `bassterlord` on Exploit. You do
not observe a human. Between the two sits an attribution assessment that
may be strong, weak, contested, or wrong. If you store the handle and the
person in the same record, you have hard-coded the assessment as a fact,
and when it turns out to be wrong you cannot cleanly unwind it — every
edge you drew now points at the wrong thing with no record of why.

**Groups are not stable containers.** Crews rebrand under pressure, split
after disputes, and run affiliate programmes where the same operator works
for three brands at once. Conti became Black Basta, Karakurt and others.
Membership is an interval, not a flag.

**Roles belong to relationships, not people.** Someone is not "a
negotiator." They were the negotiator *for this group, during this period*.
The same person is an affiliate elsewhere. Role as a property of the actor
loses that; role as a property of the membership edge keeps it.

## The three layers

```
   ASSESSED          PERSON ────────────── PERSON
   (who they are)      │                      │
                       │ ATTRIBUTED_TO        │        confidence-scored,
                       │ (confidence)         │        reversible
   ─────────────────── ┼ ──────────────────── ┼ ────────────────────────
   OBSERVED          IDENTITY ── VOUCHED_FOR ─ IDENTITY
   (what you saw)      │  ╲                     │
                       │   ╲ MEMBER_OF          │ POSTS_ON
                       │    ╲ [2023-06 → now]   │
                       │     ╲                  │
                       │      GROUP           FORUM
   ─────────────────── ┼ ──────────────────── ┼ ────────────────────────
   ATOMIC            SELECTOR              SELECTOR
   (the observable)  jabber, PGP fpr,      telegram id, BTC addr
                     forum uid
```

- **Selector** — an atomic observable. Normalised, exact-matchable, the
  join key for entity resolution.
- **Identity** — a persona. What actually posts, trades, vouches. Most
  analysis happens here, and much of it never needs to reach the layer
  above.
- **Person** — an assessed natural human. Created only when you have an
  attribution worth recording. Many cases never create one, and that is
  a healthy sign, not a gap.

Analysts work at the identity layer and *promote* to the person layer when
attribution firms up. The UI should make this promotion an explicit,
ceremonial action with a rationale field, because it is the single most
consequential judgement in the case.

## Assertions: the provenance spine

Every claim is a row in `assertion`:

> *source S, via basis B, at time T, claims that [node N has attribute A]
> or [edge E exists], graded reliability R / credibility C, with analyst
> confidence F, because: rationale.*

The graph you render is a **projection of the current, non-retracted
assertions**. This buys you four things that are extremely hard to retrofit:

1. **Retraction propagates.** A source turns out to be a rip artist. Retract
   their assertions and watch which parts of the network dissolve. Without
   an assertion layer you are hand-auditing hundreds of edges.
2. **"What did we know, and when."** Bitemporal storage answers the
   disclosure question and the after-action question with a query rather
   than an archaeology project.
3. **Disagreement is representable.** Two analysts can hold opposing
   assertions about the same edge. The model does not force premature
   consensus.
4. **Grading is per-claim, not per-source.** The same forum can be
   A2 on its own moderation actions and E5 on gossip about rivals.

### Admiralty grading

Two independent axes, per the NATO/UK standard. Do not average them into a
single star rating — the whole point is that they vary independently.

| Reliability | | Credibility | |
|---|---|---|---|
| A | Completely reliable | 1 | Confirmed by other sources |
| B | Usually reliable | 2 | Probably true |
| C | Fairly reliable | 3 | Possibly true |
| D | Not usually reliable | 4 | Doubtful |
| E | Unreliable | 5 | Improbable |
| F | Cannot be judged | 6 | Cannot be judged |

Analytic confidence (ICD 203: low/moderate/high) is a **third, separate**
field. Corroborating C3 sources can support high confidence; a single A1
source on a novel claim usually should not.

## Temporal model

Two clocks, everywhere:

- **Valid time** (`valid_from`, `valid_to`) — when it was true in the world.
- **System time** (`recorded_at`, `superseded_at`) — when you believed it.

This is what makes the "replay the network over time" feature possible, and
it is why the sociogram can animate a group fragmenting after an arrest.
Retrofitting bitemporality is a rewrite; build it in now.

Practical rule: `valid_to IS NULL` means *ongoing*, not *unknown*. Use a
separate `valid_to_certainty` in `attrs` if you need to distinguish
"still a member" from "lost track of them in 2023."

## Signed edges and trust

Criminal trust networks are **signed graphs**. Vouches are positive edges;
rip reports, ban actions and disputes are negative. Storing only positive
ties throws away the most diagnostic signal in the data.

With signs you can apply structural balance theory: triads that are
unbalanced (A vouches for B, B vouches for C, A accuses C) are unstable and
tend to resolve. Unbalanced triads are therefore excellent leads — either
your data is wrong, or a relationship is about to break, or someone is
running a persona split. This is a genuinely differentiating feature and
almost nothing in the commercial market does it well.

Trust also decays. A vouch from 2019 is not a vouch from last month. Apply
a half-life to trust edge weight in the analytics projection rather than
mutating the stored weight.

## Two-mode (affiliation) networks

UCINET's core strength, and worth matching. Actor × forum, actor × wallet,
actor × campaign are all bipartite. You project them to one-mode
co-affiliation networks — "these two identities posted in the same eleven
threads" — which is often how you find a cell that never communicates
directly on the record.

Keep the bipartite structure in the graph (`POSTS_ON`, `PARTICIPATED_IN`)
and generate the projection at analysis time. Do not pre-materialise
co-affiliation edges into the main graph or you will double-count in every
centrality calculation.

## Entity resolution

Merging is the operation most likely to quietly corrupt a case.

**Rules:**
- Auto-merge only on a single `is_strong` selector match (PGP fingerprint,
  Telegram numeric ID, forum UID). Never on nickname similarity.
- Every merge is reversible: the losing node sets `merged_into_id` rather
  than being deleted, and its edges are re-pointed with a record of the
  original endpoints.
- Merges require `graph.merge` with step-up auth, and generate an audit
  event and a case-owner notification.
- Weak signals (stylometry, timing correlation, avatar reuse) produce
  `proposal` rows for human review. They never merge.

**Nickname reuse is the trap.** `admin`, `support`, `shop` and the like are
not identifying. Maintain a stoplist of high-frequency handles and refuse
to treat them as evidence of anything.

**Telegram specifically:** `@username` is reassignable after release; the
numeric user ID is durable. Store both, weight only the ID. Analysts get
this wrong constantly and it produces confident, wrong attributions.

## What "plausible sociogram" must not mean

You wrote "generate, realtime a plausible sociogram." Worth being precise,
because there are two readings and only one is safe.

**Safe:** render the asserted graph accurately and in real time, with
layout that makes structure legible.

**Unsafe:** synthesise plausible-looking links to fill gaps. An intelligence
graph that invents relationships is worse than no graph, because it looks
authoritative and gets acted on.

The middle path, which is what you actually want: the system *may* compute
**link predictions** (co-occurrence, shared infrastructure, temporal
co-presence, stylometric similarity) and surface them as **hypotheses** —
dashed, confidence-shaded, excluded from metrics by default, each with an
explanation of the signal that generated it. An analyst promotes one to an
asserted edge by supplying evidence. The visual distinction between
"observed" and "suggested" must survive every export, screenshot and
report, because that is the distinction that will matter if the case is
ever challenged.
