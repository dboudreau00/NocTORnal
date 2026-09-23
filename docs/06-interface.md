# 06. Interface

## Design brief

An analyst runs this for six hours at a stretch, in a dim room, holding a
mental model of a few hundred entities. The interface has one job: make
structure legible without adding noise. Every pixel that is not carrying
information is competing with the graph.

Dark, but not the default "near-black plus one acid accent" that every
security dashboard ships with. Two decisions push it somewhere specific:

**The canvas is the darkest surface, not the panels.** Inverted from the
usual pattern. The graph sits on a deep plum-black void; the chrome around
it is lit glass over plum that recedes rather than glows. Edges and nodes
are the brightest things on screen because they are the content. The
ground is not flat: the key light the rest of the room is lit by falls
across the top of it, and a faint graph-paper grid in world space gives pan
and zoom something to move against. Both are held to measured ceilings
(theme.css, test_theme_contract): the key light keeps the canvas at or
below `--surface-0` at its brightest point, so this rule holds everywhere
and not only on average, and no mark drawn on the ground falls under its
contrast floor where a grid line crosses the light.

**Colour is reserved for meaning.** Node type, confidence and edge sign are
the only things allowed to use hue. Buttons, panels, borders and chrome are
strictly neutral. The moment a "Save" button is as colourful as a
high-betweenness node, the visualisation stops working. The one chrome
colour is the accent, and it is spent on state (focus, selection, the
active rail tab, the trend line, the playhead) and on exactly one piece of
identity: the TOR in the NocTORnal wordmark.

## Tokens

theme.css is the source of truth ("Mulberry Nocturne"); this table quotes
it, and test_theme_contract holds the confidence steps and the canvas
tokens here to the theme's values.

```
/* Surfaces: black-plum, wine-shifted rather than blue-shifted */
--void            #140C13   /* the canvas ground, the deepest point */
--surface-0       #1A1017   /* app background */
--surface-1       #21151F   /* rail, app bar, inspector ground */
--surface-2       #2D2030   /* raised: inputs, buttons, sticky headers */
--surface-3       #3A2A3C   /* hover, selected row */
--hairline        rgba(255, 255, 255, 0.10)   /* 1px dividers */

/* Text: porcelain, warmed to sit on plum */
--text-primary    #F1E9EA
--text-secondary  #B9A8AE
--text-tertiary   #8A7885   /* metadata, timestamps, edge types */

/* Single chrome accent: verdigris. Focus, selection, the active rail
   tab, the trend line, the playhead, and identity (the TOR in the
   wordmark, and nothing else). Deliberately NOT acid green. */
--accent          #4FC1AF
--accent-dim      #2C7B6E
--accent-glow     rgba(79, 193, 175, 0.16)

/* Semantic: signal only, never decoration */
--sign-positive   #4FB477   /* vouch, trust */
--sign-negative   #D8636B   /* rip report, dispute, ban */
--sign-neutral    #8A7C90   /* the dimmest mark on the canvas */
--alert           #E0A458   /* watch hit, review needed */
--danger          #E0574F   /* destructive, break-glass */

/* Node type hues: distinguishable at 6px, apart from each other and
   from --sign-positive and --sign-negative by CIE76 20 or more.
   --context is near-neutral on purpose ("not an actor") and sits
   close to --sign-neutral; a disc and a line do not trade meanings */
--actor-persona   #6E93C8
--actor-person    #9B7BD4
--actor-group     #E08A4B
--artefact-infra  #52B3C9
--artefact-finance #CFBF6A
--artefact-malware #D97BA8
--context         #95909B   /* near-neutral: "not an actor" */

/* The canvas ground. The key light is painted once per canvas size;
   the grid is one filled path, so a crossing composites once. */
--canvas-grid     rgba(241, 233, 234, 0.016)
--canvas-keylight rgba(241, 233, 234, 0.02)
--canvas-keylight-out rgba(241, 233, 234, 0)

/* Node body alpha, one step per confidence grade. The ring and the
   core take the --conf-* steps below. */
--canvas-node-body-high     0.66
--canvas-node-body-moderate 0.44
--canvas-node-body-low      0.3
/* Canvas labels: --text-secondary at this alpha on a --void plate */
--canvas-label-alpha        0.8

/* Confidence encodes as opacity, not hue. Hue is already spent.
   theme.css owns these three numbers and app.js reads them from the
   computed style, so the canvas and the DOM dim by the same steps.
   The floor is 0.58, not 0.45: at 0.45 the lowest step composited
   below 4.5:1 on a card (test_theme_contract holds it). */
--conf-high       1
--conf-moderate   0.74
--conf-low        0.58
```

## Type

- **Display / headings:** Söhne, or GT America. Something with a real grotesk
  personality rather than Inter, which is the sans-serif equivalent of not
  choosing. Tight tracking on headings.
- **Body / UI:** Inter is acceptable here, utility work, high legibility at
  13px, and it should not draw attention.
- **Data, selectors, hashes:** JetBrains Mono. Every wallet address, hash,
  handle and ID renders monospace, always. Analysts compare these strings
  visually and proportional type makes that error-prone.
- Scale: 11 / 12 / 13 / 15 / 18 / 24 / 32. Dense. 13px is the workhorse.
  Canvas labels are 11px mono: a handle is an identifier.

## Layout

```
┌────────────────────────────────────────────────────────────────┐
│ CASE OP-KESTREL-24        TLP:AMBER    ⏱ as-of: now    ⌘K      │  40px
├──────┬───────────────────────────────────────────┬─────────────┤
│      │                                           │             │
│ RAIL │            SOCIOGRAM CANVAS               │  INSPECTOR  │
│      │                                           │             │
│ ◇    │  (--void ground, key light, world grid)   │  selected   │
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
the canvas. Drag it and the graph plays through history, edges appear and
grey out, groups fragment, communities re-form. It is the feature that
makes bitemporal storage visible, and no competing product does it well.
Everything else stays quiet so this can be the memorable thing.

Density markers on the scrubber show collection volume, so gaps in coverage
are visible rather than being mistaken for gaps in activity. That
distinction matters enormously and is invisible in every tool I know of.

## Sociogram interaction

- **Left-drag** pan, **scroll** zoom. (Right-drag marquee select is
  designed, not built.)
- **Click** node → inspector; **double-click** → focus ego network at depth 1
- **Click** a tie → its inspector. Two ties on one pair bow apart, so each
  can be seen and each can be clicked; the nearest one under the pointer
  answers. A selected tie with a twin on its pair says so on the canvas
  ("tie 1 of 2 between these two").
- **Hover** → dim everything beyond the neighbourhood, no tooltip delay
- **Shift-click** two nodes → shortest path highlight
- Selected node's community tints; the rest desaturates (designed, not
  built)
- Space bar → temporarily hide all inferred edges. One key, instant
  answer to "what do I actually *know*?" Use it constantly.
- Keyboard: arrows step the selection; `[`/`]` step through the selected
  entity's ties, the ties on one pair next to each other; Shift with an
  arrow pans; Home returns to the selection; `+`/`-` zoom; `0` fits;
  Enter opens the ego network; `P` marks a path anchor.
- Reveal: a selection made anywhere but a click on the canvas (the arrow
  and bracket keys, the palette, a search hit, the entity table, from any
  tab) pans the view to centre it when its disc is not wholly on the
  canvas. A selection made on another tab is revealed when the graph tab
  is shown again, and choosing the same entity again after panning it
  away brings it back. Three things never pan: a click (what was clicked
  is under the pointer already), an entity Fit placed (the test is never
  stricter than Fit's own margin, so selecting on a fitted view keeps the
  fit), and a re-render (a scrubber step, a projection change) with the
  selection unchanged. The zoom is never touched.
- **Fit** frames every entity, the unconnected ones included, at any
  window size. Entities with no tie in the projection are laid out on a
  labelled shelf beside the connected graph rather than scattered by the
  layout. A new case opens fitted. Until the analyst pans or zooms, the
  view stays the fit: it follows the layout as it settles, and re-fits
  after a projection change, a scrubber step or a window resize. The
  first pan or zoom makes the view the analyst's, and from then on only
  `0` or Fit re-frames it (and makes it the fit again); when entities are
  outside the view, the canvas says how many.

**Visual encoding, the rules that must never bend:**

| Property | Encodes |
|---|---|
| Node size | Chosen centrality metric (analyst picks; label states which) |
| Node colour | Node type: a translucent body in the type hue, and a type ring inset inside the disc |
| Node opacity | Confidence, and nothing else. The body takes `--canvas-node-body-*`, the ring and core take `--conf-*`, the same at every radius. An entity with no tie that meets the filter takes the LOW step, never full opacity |
| Node shape | Evidence (E2, while "Mark unevidenced" is on): body and solid core = rests on an exhibit; hollow, `--void` inside the ring and no core = rests on none |
| State rings | Outside the node and at least 3px clear of the type ring, innermost first: unreviewed proposal (dashed `--alert`), selected (`--accent`), pinned (dotted), path anchor (dashed `--accent`), ego centre (`--accent-dim`) |
| Edge colour | Sign: green positive, red negative, grey neutral |
| Edge width | Weight, log-scaled over the projection's own lightest-to-heaviest range (0.9 to 2.8px); all ties of equal weight draw at the middle |
| **Edge style** | **Solid = asserted. Dashed = inferred. Never negotiable.** |
| Edge bead | Evidence (E2): a hollow bead at a tie's midpoint = rests on no exhibit. A shape, never a fade (opacity is confidence) and never a dash (dashed is inferred) |
| Sign mark | `+` / `-` at a tie's midpoint from 120% zoom, so sign is never hue alone |

Labels: the selected entity and the one under the pointer are always
named. Every other name is placed largest node first, below, above, right
or left of its node, and only where it covers no node, bead, sign mark or
other name; zooming in makes room for more, and the legend says how many
were held back. Each name sits on a `--void` plate so a tie crossing it
cannot read as part of the string. Edge types appear from 190% zoom where
they fit. Everything visible at once is a hairball.

## Other surfaces

- **Triage**: three-pane: watch hits, document, extractions. Keyboard
  driven: `J`/`K` navigate, `L` link, `D` discard, `P` propose. Someone
  works this queue for an hour at a time; every mouse trip is a tax.
- **Entity page**, the Obsidian-like view. Backlinks panel showing every
  assertion, document and evidence item referencing this entity. Analysts
  navigate by association, not hierarchy.
- **Assertion inspector**, every claim with source, grading, rationale,
  and a retract control. Reachable in one click from any edge, because
  "why do we believe this?" is the most-asked question in the product.
  A tie's inspector also has **Add a claim about this tie**: a further
  assertion with its own basis, grading, rationale and exhibit, graded
  by the analyst exactly as the Add relationship form is (nothing is
  chosen for them). A tie's confidence is the highest grade among its
  live claims, so Correct... can raise a tie and cannot lower it past a
  claim that still stands. Asked to lower one, it stops before the
  reason is written, opens this form with the lower grade chosen, and
  says the rest: record the lower claim, then retract each higher one
  with its reason. The tie stays on the graph throughout, keeps a graded
  claim and its exhibit, and the withdrawn grade stays on the record.
- **Command palette** (`⌘K`), jump to entity, run metric, create node,
  switch projection. Power users will live here. It matches names in
  memory and asks `GET /cases/{id}/search/selectors` for the rest, so a
  pasted wallet, handle or key finds the entity that holds it, named with
  the selector that matched.
- **Search pane.** One query, three per-kind routes on the open case:
  `GET /search/nodes`, `/search/selectors` and `/search/evidence`. A node
  matches by word start over its label and attributes, by any fragment of
  its label, or through a selector attributed to it; each hit reached
  through a selector carries `via` (the type, the value as observed,
  whether it matched exactly, and the merged record that holds it when
  that is not the entity itself). EXACT means the selector's per-type
  canonical form or its observed bytes, never a case-blind comparison of
  the raw value, and an exact label or selector ranks 1.0 above every
  fragment. A labelled query (`ICQ: 1234`, `Jabber: ember`) matches that
  type only. Every route filters by the caller's own clearance and
  compartments in SQL, so the cap applies after filtering, and a selector
  on a node the caller may not see is never matched, counted or named.
  `with_total=true` returns `{hits, total, limit}`, and the pane says
  "showing 50 of 73" rather than cutting the list silently. The per-kind
  routes read this case only, so a break-glass grant on it raises them;
  the combined `GET /search` does not, because its collected documents
  belong to every source.

## Quality floor

Keyboard focus visible on every control. `prefers-reduced-motion` respected,
the graph settles instantly instead of animating. Canvas keyboard
navigable for selection and for panning. No colour-only encoding: sign is
also conveyed by a `+` / `-` mark on the tie, confidence also by a numeric
badge in the inspector, evidence by shape. Dense information design still
has to be operable at 200% zoom, and at 1366x768 the whole flagship case
still fits on the canvas.
