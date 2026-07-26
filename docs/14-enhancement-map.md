# 14 — Enhancement map

Written 2026-07-25, after Phase 2 shipped and after a first real session of
hand-building a case (OP-NIGHTJAR-26 and OP-Test-3). Ordered by payoff
against cost, and grounded in what actually happened when the tool was used
rather than in what the roadmap assumed.

## What the first real session revealed

**A bug the roadmap could not have predicted.** `OP-Test-3` was created
AMBER_STRICT and stayed empty. The entity forms defaulted an element's
classification to a hardcoded AMBER, which is *below* an AMBER_STRICT case's
floor, so the database refused every entity and the UI showed an opaque 400.
Fixed: the forms now default to the case's own classification and offer only
legal values. The general lesson is that **any UI default that can violate a
database constraint will**, and the constraint is right — the default was
wrong.

**Zero evidence, in a system whose thesis is chain of custody.** Seven
entities, seven relationships, fourteen assertions, three selectors — and no
exhibits. The evidence path works (it is tested end to end), but nothing in
the interface *asks* for an exhibit, so nothing got attached. See E1 below;
this is the single biggest gap between the product as built and the product
as pitched.

**The grading axes were used properly.** Ten distinct
basis/reliability/credibility/confidence combinations across fourteen
assertions, including two `ANALYST_INFERENCE` claims with rationales. The
Admiralty model is not being defaulted away, which is the main risk with a
two-axis grading scheme.

**The Communication projection is empty.** Not a bug — a finding. No
communication ties have been recorded, so the preset correctly shows nothing.
That is exactly what projections are for, and it argues for C1.

**A broker signature is already visible.** `spectre_lynx` has degree 3 and
local clustering 0.0 — its neighbours do not know each other. High degree
with low clustering is the structural signature Burt's constraint measures
properly, and it is the thing docs/13 says the market does badly. Phase 3
should lead with it.

---

## E — Evidence and provenance (highest payoff)

**E1. Make evidence the path of least resistance, not a separate tab.**
Today an analyst creates an entity, then must navigate elsewhere to upload an
exhibit and elsewhere again to link it. Instead: an "attach exhibit" affordance
inside the entity and relationship forms, and an assertion that can carry a
file at the moment the claim is made. The assertion model already has
`evidence_id`; nothing in the UI uses it. *Cost: small. Payoff: the
difference between a graph of opinions and a graph of evidence.*

**E2. Show provenance strength on the graph, not only in the inspector.**
Confidence is already encoded as node opacity, but an analyst cannot see
which edges are *unevidenced*. Ring or hatch elements whose assertions have
no `evidence_id`. A case is defensible in proportion to how much of it is
evidenced, and that should be visible at a glance.

**E3. Retraction, in the interface.** `retract_assertion` exists in the
service and is exposed nowhere. Retracting a source and watching the network
dissolve is the demo that sells the assertion model, and it is currently
impossible to do from the UI.

**E4. Recovery codes.** docs/05 specifies ten single-use Argon2id-hashed
codes and they were never built. The TOTP lockout during this session had no
proper escape hatch — `bootstrap session` is a development workaround, not
an answer. *Cost: small. This is a correctness gap against the spec.*

## C — Collection and coverage

**C1. Coverage indicators, so absence of data reads as absence of data.**
docs/06 asks for density markers on the scrubber for exactly this reason. An
empty Communication projection must be visibly "not collected", never
mistakenly "no communication". Extend to the entity level: an actor on a
platform with no viable collection route should read UNMONITORED.

**C2. Manual capture before adapters.** Decision 18 put Telegram *capture*
in scope and deferred monitoring. A paste-a-conversation-export path that
lands a document, extracts selectors with offsets, and proposes graph
changes would exercise the whole proposal pipeline without any of the
persona-management risk.

## A — Analytics (Phase 3, and the differentiators)

**A1. Burt's constraint and effective size.** docs/03 calls it arguably the
most useful metric here, and docs/13 notes almost no competing tool surfaces
it. The clustering signal above is a hint of it; the real measure is the
product's sharpest claim.

**A2. Betweenness with the low-degree/high-betweenness callout.** The UI
should teach the pattern, not just print a number.

**A3. Signed structural balance.** Unbalanced triads are leads, and the data
model already carries signs. `spectre_lynx` being both vouched for and
accused is precisely the shape to surface.

**A4. Key player (KPP-Neg) with a fragmentation preview.** "Which n actors,
removed, break this network" is a different answer from "the top n central
actors", and that surprise is the value.

Note the honest constraint: these need igraph in an analytics worker. The
local metrics shipped in Phase 2 (degree, weighted, signed, clustering,
k-core) are exact and synchronous because the graphs are small; betweenness
and community detection are not, and pretending otherwise would produce slow
requests and wrong numbers.

## U — Interface debt

**U1. sigma.js and ForceAtlas2 in a worker.** docs/02 specifies these; the
canvas is currently hand-rolled because a strict CSP and no build step ruled
out a bundler. It is adequate at tens of nodes and will not hold at
thousands. Adopting a bundler is the real decision here, and it is a
deviation worth recording rather than quietly leaving.

**U2. Why is this hidden?** An under-cleared analyst sees a smaller graph
with no indication that anything was withheld. A non-disclosing count
("3 elements not shown at your clearance") preserves need-to-know while
removing the impression that the case is smaller than it is. Needs care: the
count itself is a weak signal, so it may need to be a per-case setting.

**U3. Temporal replay needs temporal data.** The scrubber works, but nothing
sets `valid_from`/`valid_to`, so there is nothing to replay. The entity and
relationship forms should ask for the interval — "was in LockBit until
March" is the normal case, not the exception.

**U4. Bulk entry.** Hand-typing seven entities was tolerable; seventy will
not be. A paste-a-list path, and duplicate detection against existing
labels and selectors before creating anything.

## O — Operational

**O1. CI.** Phase 0 lists lint, typecheck, test and a migration round-trip;
all four are run by hand today.

**O2. The deferred security items**, unchanged and still deliberate: rate
limiting, session IP/UA binding, the destination-aware TLP egress gate, the
API running as a non-owner database role, and a compartment registry. All
recorded in `apps/api/README.md` and `docs/00-decisions.md`.

**O3. The host clock.** This machine's clock is unsynchronised, which is why
TOTP cannot work against a phone here. Worth fixing at the environment level
rather than routing around forever.
