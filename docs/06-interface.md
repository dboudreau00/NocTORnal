# 06 — Interface

## Design brief

An analyst runs this for six hours at a stretch, in a dim room, holding a
mental model of a few hundred entities. The interface has one job: make
structure legible without adding noise. Every pixel that is not carrying
information is competing with the graph.

Dark, but not the default "near-black plus one acid accent" that every
security dashboard ships with. Two decisions push it somewhere specific:

**The canvas is the darkest surface, not the panels.** Inverted from the
usual pattern. The graph sits in a deep, slightly blue void; the chrome
around it is a lighter slate that recedes rather than glows. Edges and
nodes are the brightest things on screen because they are the content.

**Colour is reserved for meaning.** Node type, confidence and edge sign are
the only things allowed to use hue. Buttons, panels, borders and chrome are
strictly neutral. The moment a "Save" button is as colourful as a
high-betweenness node, the visualisation stops working.

## Tokens

```
/* Surfaces — cool slate, blue-shifted, low chroma */
--void            #080B12   /* graph canvas — the deepest point */
--surface-0       #0E121B   /* app background */
--surface-1       #151A26   /* panels */
--surface-2       #1E2432   /* raised: cards, menus, inputs */
--surface-3       #2A3141   /* hover, active rows */
--hairline        #303849   /* 1px dividers, used generously */

/* Text */
--text-primary    #E4E8F0
--text-secondary  #98A2B8
--text-tertiary   #626C82   /* metadata, timestamps */

/* Single chrome accent — desaturated cyan-teal.
   Deliberately NOT the acid green / vermilion default. */
--accent          #4EA8A0
--accent-dim      #2F6B66
--accent-glow     rgba(78,168,160,0.18)

/* Semantic — signal only, never decoration */
--sign-positive   #3E9C6B   /* vouch, trust */
--sign-negative   #C05A4E   /* rip report, dispute, ban */
--sign-neutral    #6B7690
--alert           #D4A03C   /* watch hit, review needed */
--danger          #C0473C   /* destructive, break-glass */

/* Node type hues — muted, evenly spaced, distinguishable at 6px
   and under the common colour-vision deficiencies */
--actor-persona   #6E8FD4
--actor-person    #9B7FD4
--actor-group     #D48A5C
--artefact-infra  #5CA8C4
--artefact-finance #C4A85C
--artefact-malware #C46E8A
--context         #7F8A9B

/* Confidence encodes as opacity, not hue — hue is already spent */
--conf-high       1.00
--conf-moderate   0.72
--conf-low        0.45
```

## Type

- **Display / headings:** Söhne, or GT America. Something with a real grotesk
  personality rather than Inter, which is the sans-serif equivalent of not
  choosing. Tight tracking on headings.
- **Body / UI:** Inter is acceptable here — utility work, high legibility at
  13px, and it should not draw attention.
- **Data, selectors, hashes:** JetBrains Mono. Every wallet address, hash,
  handle and ID renders monospace, always. Analysts compare these strings
  visually and proportional type makes that error-prone.
- Scale: 11 / 12 / 13 / 15 / 18 / 24 / 32. Dense. 13px is the workhorse.

## Layout

```
┌────────────────────────────────────────────────────────────────┐
│ CASE OP-KESTREL-24        TLP:AMBER    ⏱ as-of: now    ⌘K      │  40px
├──────┬───────────────────────────────────────────┬─────────────┤
│      │                                           │             │
│ RAIL │            SOCIOGRAM CANVAS               │  INSPECTOR  │
│      │                                           │             │
│ ◇    │         (--void, edge to edge)            │  selected   │
│ ⬡    │                                           │  entity     │
│ ▤    │                                           │             │
│ ⚑    │                                           │  assertions │
│ ⚙    │                                           │  evidence   │
│      │                                           │  metrics    │
│ 56px ├───────────────────────────────────────────┤  360px      │
│      │  TIMELINE SCRUBBER  ◄──────●───────────►  │             │
└──────┴───────────────────────────────────────────┴─────────────┘
```

**The timeline scrubber is the signature element.** A persistent strip under
the canvas. Drag it and the graph plays through history — edges appear and
grey out, groups fragment, communities re-form. It is the feature that
makes bitemporal storage visible, and no competing product does it well.
Everything else stays quiet so this can be the memorable thing.

Density markers on the scrubber show collection volume, so gaps in coverage
are visible rather than being mistaken for gaps in activity. That
distinction matters enormously and is invisible in every tool I know of.

## Sociogram interaction

- **Left-drag** pan, **scroll** zoom, **right-drag** marquee select
- **Click** node → inspector; **double-click** → focus ego network at depth 1
- **Hover** → dim everything beyond the neighbourhood, no tooltip delay
- **Shift-click** two nodes → shortest path highlight
- Selected node's community tints; the rest desaturates
- Space bar → temporarily hide all inferred edges. One key, instant
  answer to "what do I actually *know*?" Use it constantly.

**Visual encoding — the rules that must never bend:**

| Property | Encodes |
|---|---|
| Node size | Chosen centrality metric (analyst picks; label states which) |
| Node colour | Node type |
| Node opacity | Confidence |
| Node ring | Selected / pinned / has unreviewed proposals |
| Edge colour | Sign: green positive, red negative, grey neutral |
| Edge width | Weight (log-scaled — raw counts destroy the scale) |
| **Edge style** | **Solid = asserted. Dashed = inferred. Never negotiable.** |

Progressive disclosure: labels appear above a zoom threshold, edge labels
above a higher one. Everything visible at once is a hairball.

## Other surfaces

- **Triage** — three-pane: watch hits, document, extractions. Keyboard
  driven: `J`/`K` navigate, `L` link, `D` discard, `P` propose. Someone
  works this queue for an hour at a time; every mouse trip is a tax.
- **Entity page** — the Obsidian-like view. Backlinks panel showing every
  assertion, document and evidence item referencing this entity. Analysts
  navigate by association, not hierarchy.
- **Assertion inspector** — every claim with source, grading, rationale,
  and a retract control. Reachable in one click from any edge, because
  "why do we believe this?" is the most-asked question in the product.
- **Command palette** (`⌘K`) — jump to entity, run metric, create node,
  switch projection. Power users will live here.

## Quality floor

Keyboard focus visible on every control. `prefers-reduced-motion` respected
— the graph settles instantly instead of animating. Canvas keyboard
navigable for selection. No colour-only encoding: sign is also conveyed by
edge style, confidence also by a numeric badge in the inspector. Dense
information design still has to be operable at 200% zoom.
