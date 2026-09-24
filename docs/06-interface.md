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
   close to --sign-neutral; a disc and a line do not trade meanings.
   Under simulated deuteranopia and protanopia every pair is 10 or
   more apart, or the two differ in outline (the canvas draws context
   as a diamond; Persona and Assessed person are 19 apart and a person
   also carries a second ring) */
--actor-persona   #6E93C8
--actor-person    #9679E7
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
The strip counts world time only (an entity's valid-from or first-seen, a
tie's valid-from): an element that carries nothing but the time it was
entered is counted in the note as undated and is not drawn, because an
import date is not history. Bar height grows with the square root of the
count, so one busy stretch cannot flatten every other month to the floor,
and the playhead is a 1px line under a caret, so the bar at "now" stays
readable.

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
  answer to "what do I actually *know*?" Use it constantly. It works from
  anywhere on the graph tab, the timeline slider and the inspector
  included, and from the rail's Graph tab once it is selected, except
  where Space already does something: a field, a control
  reached with the keyboard (whose Space presses it), or an inspector
  button just used. A pointer on a projection, timeline or canvas control
  hands focus back to the canvas, so after a click Space peeks again. While
  it is held the canvas says how many inferred ties it hid.
- **Dragging a node pins it** where it is put (a click that moves less
  than 3px neither moves nor pins); `U` (or the Pin / Unpin button that
  appears on the canvas for a selected entity) pins or unpins one entity.
  Save layout carries a dot while hand placements are unsaved; leaving the
  page with them asks first, switching case saves them to the case they
  were made in, with a message, and re-reading the same case (a title or
  status change) keeps them, still unsaved. A status change that makes
  the case read-only (CLOSED, ARCHIVED, PURGED) saves them first, with a
  message, because nothing can store them afterwards; on a read-only case
  a placement stays in the view and is never marked unsaved. Clear pins counts what it
  will unpin (inside a focus, only what is on screen), asks, stores only
  those pins, and offers Undo on a message that stays until it is used
  or dismissed.
- Keyboard: arrows step the selection; `[`/`]` step through the selected
  entity's ties, the ties on one pair next to each other; Shift with an
  arrow pans; Home returns to the selection; `+`/`-` zoom; `0` fits;
  Enter opens the ego network; `P` marks a path anchor; `U` pins or
  unpins the selection. The hint strip under the canvas and the `?` sheet
  list all of them.
- The zoom level is shown on the canvas, with `-`, `+` and Fit beside it
  and the count of names held back for lack of room.
- What changes how the picture may be read sits ON the canvas, top left:
  how much of it rests on an exhibit (counted from the projection itself,
  so it never depends on the metered metrics call; during an ego or set
  focus it counts the focus drawn, says so, and gives the whole
  projection's figure in its title), a truncated page,
  material above the reader's clearance, and metrics that did not load
  (retried by itself when the refusal says when). The readout under the
  legend says what is drawn in words.
- An empty canvas says whether the case or the projection is empty, and
  offers the one thing that would fill it: add the first entity, change
  the case status, move the as-of position back to now, or reload. The
  layout controls are disabled while nothing is drawn.
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
  window size, and keeps them clear of the canvas's own chips and buttons
  along the top and the foot. Entities with no tie in the projection are laid out on a
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
| Node size | Chosen centrality metric (analyst picks; label states which). AREA in proportion to the value, from zero: radius = 16px x sqrt(value / largest), floor 5px, at 100% zoom; the largest is taken over the connected entities. A size key in the legend draws two values at the current zoom |
| Node colour | Node type: a translucent body in the type hue, and a type ring inset inside the outline |
| Node outline | Node type again, so type is never hue alone: a victim is a square, context (events, incidents, places) a diamond, an assessed person has a second ring inside the first, everything else is a disc. Every outline can be hollow |
| Node opacity | Confidence, and nothing else. The body takes `--canvas-node-body-*`, the ring and core take `--conf-*`, the same at every radius. An entity with no tie that meets the filter takes the LOW step, never full opacity |
| Node shape | Evidence (E2, while "Mark unevidenced" is on): body and solid core = rests on an exhibit; hollow, `--void` inside the ring and no core = rests on none |
| State rings | Outside the node and at least 3px clear of the type ring, innermost first: a proposal waiting in Triage or a tie still PROPOSED (dashed `--alert` on a `--void` backing; the inspector's rows say which), selected (solid `--accent`), pinned (dotted), path anchor (dashed `--accent`), ego centre (a double ring in `--accent-dim`). Each has its own pattern and its own legend entry |
| Edge colour | Sign: green positive, red negative, grey neutral |
| Edge width | Weight, log-scaled over the projection's own lightest-to-heaviest range (0.9 to 2.8px); all ties of equal weight draw at the middle |
| **Edge style** | **Solid = asserted. Dashed = inferred. Never negotiable.** |
| Edge bead | Evidence (E2): a hollow bead at a tie's midpoint = rests on no exhibit. A shape, never a fade (opacity is confidence) and never a dash (dashed is inferred) |
| Sign mark | `+` / `-` at a tie's midpoint from 120% zoom, so sign is never hue alone |

Labels: the selected entity and the one under the pointer are always
named. Every other name is placed largest node first, below, above, right
or left of its node, and only where it covers no node, bead, sign mark or
other name and no chip or button of the canvas's own (a name cut by one
reads as a different, shorter handle); zooming in makes room for more,
and the canvas says how many were held back, beside the zoom level. Each name sits on a `--void` plate so a tie crossing it
cannot read as part of the string. Edge types appear from 190% zoom where
they fit. Everything visible at once is a hairball.

## Other surfaces

- **Triage**: three-pane: watch hits, document, extractions. Keyboard
  driven: `J`/`K` navigate, `A` accept, `R` reject (with a reason), `D`
  defer (park it as unresolved, with a note). Someone works this queue
  for an hour at a time; every mouse trip is a tax. The keys act only
  while the queue's list has the focus, never in a field, on a button,
  under a Ctrl, Alt or Cmd chord or with a dialog open, and the keyboard
  sheet can turn them off. `A` asks before it writes, and the line above
  the queue then names what was accepted and offers an Undo that retires
  it.
  Each card names what accepting would write (the entity, the claim and
  its value for an attribute; both ends for a tie), carries the
  capture's TLP marking and accepts at it or stricter, never below, and
  opens the captured document at the match. An entity a waiting proposal
  is about is ringed on the canvas until the proposal is decided here.
- **Entity page**, the Obsidian-like view. Backlinks panel showing every
  assertion, document and evidence item referencing this entity. Analysts
  navigate by association, not hierarchy.
- **Assertion inspector**, every claim with source, grading, rationale,
  and a retract control. Reachable in one click from any edge, because
  "why do we believe this?" is the most-asked question in the product.
  A tie's inspector also has **Add a claim about this tie**: a further
  assertion with its own basis, grading, rationale and exhibit, graded
  by the analyst exactly as the Add link form is (nothing is
  chosen for them). **Correct...** is graded the same way: a correction
  is a claim, so the form under the element's actions asks for the new
  label (an entity) or the new confidence (a tie) together with a basis,
  grading, reason and optional exhibit, and nothing is filled in. The API
  refuses an ungraded claim on every write that records one, naming the
  missing field. A tie's confidence is the highest grade among its
  live claims, so Correct... can raise a tie and cannot lower it past a
  claim that still stands. Asked to lower one, it sends nothing, opens
  Add a claim holding the grading and reason already entered with the
  lower grade chosen, and says the rest: record the lower claim, then
  retract each higher one with its reason. The tie stays on the graph
  throughout, keeps a graded claim and its exhibit, and the withdrawn
  grade stays on the record.
  Under its claims and exhibits a tie has a **Review**. A tie a person
  asserts is born ACCEPTED, and a Triage acceptance is too; a tie founded
  on a machine's claim (AUTOMATED_INFERENCE) is born PROPOSED and rings
  both of its ends on the canvas. Anyone holding `proposal.review` (the
  Lead investigator or a Reviewer) accepts or disputes it, or reopens the
  review; a dispute and a reopening need a note. Each decision is audited
  as EDGE_REVIEWED and read back in the section, and the rings and the
  entity's "Ties awaiting review" count follow it at once. In an
  entity's Relationships list a PROPOSED or DISPUTED tie is marked with
  its state (and says it to a screen reader), an ACCEPTED one is not, and
  the PROPOSED ties come first among the drawn ones, so the ties that
  count asks about are the first rows to open. Ties entered
  before Alpha 6 were all left PROPOSED, whoever entered them;
  migration 0067 gives them the state
  the same rule would have given them, with an EDGE_REVIEWED row each
  that the section shows as "by the Alpha 6 upgrade", and leaves a
  machine's unaccepted tie, and any tie a person has reviewed, alone.
- **First and last seen** of an entity (the entity list's First seen
  column, the inspector's header line) are the earliest and latest
  observed times among its live claims. A retracted claim stops counting,
  and a claim about one of its ties is about the relationship, so it does
  not move them.
- **Add entity** asks before it creates. As the label is typed it lists
  same-type entities whose label matches once case and whitespace are
  folded, each with Open existing, and a match holds Create until the
  analyst presses Create anyway. A Selector, Comms account or Crypto
  wallet names its selector type, or None of these for a chain or a
  platform the ontology has no type for: the label is shown as the selector
  index will hold it, a value that reduces to nothing is refused with the
  ontology's own reason, and on create the selector is recorded against
  the new entity. One already held by another entity is reported as a
  merge lead, and the merge panel lists likely matches first. After either
  create form, the inspector opens on what was made and says so under its
  name, in the alert tone when the claim has no exhibit behind it yet; the
  note goes when the analyst moves on. The source (exhibit, observed time,
  reference) is cleared for the next entry unless "Keep" was ticked.
- **Command palette** (`Ctrl K`, `⌘K` on a Mac; the app bar's "Jump to"
  control), jump to entity, run metric, create node, switch projection.
  Power users will live here. With nothing typed it opens on the entities
  looked at most recently and the selection's commands, with the panes
  behind one "Go to a pane" row; each pane is named by its rail caption
  and found by other words too ("link", "relationship"). It matches names
  in memory and asks `GET /cases/{id}/search/nodes`, the Search pane's own
  Entities route, for the rest (a spaced query only when it names no
  command), so a pasted wallet, handle or key finds the entity that holds
  it, and an attribute finds its crew members, named with the reason the
  pane gives. Whenever a query is typed in a case, the last row is
  "Search this case for ...", which runs it in the Search pane. A jump
  from the palette or from Search centres the entity and zooms in to a
  readable scale (never out); one the projection leaves off the canvas is
  said to be off it.
- **Search pane.** One query, four per-kind routes on the open case, one
  column each: `GET /search/nodes`, `/search/evidence`, `/search/documents`
  (collected documents, which are every source's rather than this case's,
  read at the caller's own ceiling and only with the global
  `collection.read`; without it the column says it was not searched and
  names the roles that read documents) and `/search/assertions` (live
  claims, by rationale, reference, claimed value, the title of the exhibit
  cited when the caller may read exhibits, or an exact grading such as
  `C3`, each opening its entity or tie with the claim's card in view).
  `/search/selectors` remains for a client that wants selector matches
  alone. A row shows the hit's type and TLP chips and why it matched
  (its name, an attribute, a selector, a merged record, or, for a query
  whose words are spread over several parts, each part that holds one),
  never a bare rank. A node matches by word start over its label and attribute VALUES
  (never an attribute's key), by any fragment of its label, or through a
  selector attributed to it; each hit reached
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
- **Words.** One name for each thing, in every pane (ux19-copy,
  2026-09-23): an *entity* (a person, persona, group, wallet, host; "node"
  only inside metric tables, never "actor"); a *relationship* between two
  entities, recorded on the *Add link* pane ("link" is the one word for it
  a rail tile has room for, and the pane says what a link is), a
  *social tie* when its type counts in the social views and an *identity
  or other link* when it does not ("edge" only in parameters); an
  *assertion*, the claim with its source, grading and confidence; an
  *exhibit*, one item of evidence; and the *view*, which is the projection
  said in its controls' words ("View: All social ties · confidence LOW
  and above · inferred included · as of now"), with the parameters in a
  tooltip for anyone who must quote them. A rail caption is the name the
  palette answers to, and a refusal names the roles that would allow the
  action and who can give one, never a permission code.

## Quality floor

Keyboard focus visible on every control. `prefers-reduced-motion` respected,
the graph settles instantly instead of animating. Canvas keyboard
navigable for selection and for panning. No colour-only encoding: sign is
also conveyed by a `+` / `-` mark on the tie, confidence also by its word
(LOW, MODERATE, HIGH) in the inspector, evidence by shape. Dense information design still
has to be operable at 200% zoom, and at 1366x768 the whole flagship case
still fits on the canvas.
