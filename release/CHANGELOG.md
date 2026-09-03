# Changelog

## Alpha 4 — 2026-09-02

Completion release. **Still not audited, and still not lawful to operate
against real material until the five blocking items in
[docs/16](../docs/16-legal-and-external.md) are settled by somebody
outside this codebase.** Nothing in this release touches those.

This one closed gaps rather than adding surface, and most of what it
closed was a control that existed and could not be reached, or a sentence
that claimed more than the code did.

### The custody ledger is verified for the first time

`core.evidence_custody` has been hash-chained since migration 0024, under
a docstring invoking FRE 902(13)–(14) — and nothing had ever recomputed
it. The internal audit log had a verifier, a CI step and a UI button; the
record actually produced to a court had none of the three.

It now has all three: `custody_verify.py`, `GET /audit/custody/verify`
under `audit.read`, a CI step beside the audit chain, and a control in
Governance → Audit chain. It checks LINK, CONTENT, FORK and GENESIS
across the whole ledger, and because the chain is global, naming an
exhibit narrows what is *reported* and never what is checked — the scoped
answer says so rather than reading like a completeness pass.

**What it still cannot see is a tail truncation.** Deleting the newest
rows orphans nothing and needs no rehash, so the ledger still agrees with
itself. That is the first entry in the module's own list of what it cannot
see, and the response carries `last_id`, `checked` and `tail_row_hash` so
an operator recording them out of band can catch a decrease. A run-to-run
equality check on the hash is *not* the defence it looks like — the hash
changes on every honest append — and the docstring says which two checks
do work.

### Break-glass raises something

Since Alpha 3 the grant is read by `PgAccessResolver.resolve()` and does
what its docstring always promised. `record_use()` is called only when the
grant is what made an access possible, so the security officer's review
queue counts accesses the grant actually bought rather than a constant
zero.

### Controls that existed and could not be reached

- **The readiness register** — `GET /admin/readiness`, and an Admin
  section — answers what this deployment can establish about itself, with
  the evidence beside each line. It is the code-side half only: the
  docs/16 items that need a human are named as out of scope, and two items
  it *can* partly check say so in their passing evidence rather than
  leaving the operator to infer it.
- **The delivery ledger** — `notify.delivery` has recorded every refusal
  since 0029 and every destination since 0044, and nothing read it. There
  is now a route and an Inbox → Deliveries view. It carries kinds,
  channels, addresses and reasons; never subjects or summaries.
- **The assumptions register** (migration 0056) — the last named feature
  gap in Phase 6. An assumption is what the analysis takes for granted,
  and writing it down is what makes it reviewable. Open and confirmed
  statements reach the report; withdrawn and refuted ones do not.
- **Retention rules can be confirmed from the console.** The panel that
  lists unconfirmed rules offered no way to confirm one, so the only route
  was `curl`.
- **Escalation of an unacknowledged priority-1**, three registered
  notification kinds that had no producer, and a `notify_drain.py` cron
  entry.

### The compartment registry (migration 0057)

Compartments were free text, so a typo was a case nobody could see. They
are now registered, and every write site validates against the registry.

The migration refuses to run rather than silently skipping a value it
cannot register — and the decision about what to do with a legacy value
that cannot satisfy the format is stated in its docstring rather than
left to be discovered.

### Fixes worth naming

- **The purge reported bytes destroyed that were still in the bucket.**
  `EvidenceStorage.delete()` inserts a delete marker on a versioned,
  locked bucket and returns success. The purge now calls
  `delete_all_versions`, marks only rows whose objects the store confirmed
  gone, and counts exhibit ROWS in the operator-facing counter rather than
  object VERSIONS — which two docstrings had claimed it already did.
- **The evidence integrity alarm was an outbound-email amplifier.** It
  re-fired on every read of a corrupt exhibit, on a route with no rate
  limit, and each alarm then fanned out to every security officer. It is
  now idempotent while unacknowledged.
- **Strict session binding covered the HTTP path only.** A token refused
  on every request was accepted on the live event stream, where it also
  slid the idle window and kept the victim's session alive.
- **`/sources/{id}/run` returned a RED source's hostname** in its error
  string, under a module docstring certifying that route as safe.
- **`/analytics/latest` claimed `cached: true`** with no hash check, and
  the console rendered that as "unchanged since the last run" — staleness
  reported as freshness, on the pane that names people.
- The collection listing endpoints filter on the caller's ceiling;
  `suppressed` and `triage_state` have writers; search reaches
  `collect.document`. The triage write is gated on the document's label
  and its source's, because the read is.

### The console

Custody verify, the delivery ledger, the readiness register, retention
confirmation, the assumptions register, and the analytics pane showing the
last completed run instead of an empty scoreboard. `/auth/me` now carries
`display_name`, so the app bar greets an analyst by name rather than with
their own UUID.

Also: `.h3`/`.h4` were scoped to the analytics pane while three other
panes used them and got the browser's default `<h3>`; `.pane-title` had
been in the Inbox markup since it was written and was never defined; the
keyboard sheet ran past the bottom of a short viewport with its close
button on the far side; and the two widest tables now scroll inside their
own box.

### Documentation is now checked against the tree

`test_doc_invariants.py` proved that a cited *document* exists. The
roadmap is written mostly in three other currencies — source files, test
names and endpoints — and none of them were checked. Three new tests
close that: a cited module must be in the tree, a cited test must be
defined, and a cited endpoint must be routed.

The scoreboard's overall figure was corrected from ~95% to 92.7%. It had
never been recomputed after the per-phase numbers were revised downward,
so the summary and the table it summarised disagreed — which is the same
defect the document catalogues everywhere else.

### Known

The suite is not order-independent on a REUSED database:
`test_an_expired_dead_letter_can_be_purged_even_if_it_predates_0040`
passes alone and fails when an earlier test in the same session has left a
case with expired retention and unpurged evidence. It is a property of the
fixture estate, not of the purge, and a fresh database does not show it.

## Alpha 3 — 2026-09-01

Interface release. **Still not audited, and still not lawful to operate
against real material until the five blocking items in
[docs/16](../docs/16-legal-and-external.md) are settled by somebody
outside this codebase.** Nothing in this release touches those.

### The console was reskinned

Elevation now comes from LIGHT rather than paint: a translucent wash and a
hairline over a gradient ground, instead of a ladder of five opaque greys.
That is what makes a panel read as lit rather than filled, and it is the
single largest visual change here. It brings a radius scale (4/8/12/14 and
a pill), a 4px spacing scale, a shadow scale and motion tokens — the first
cut had six ad-hoc radii between 3px and 10px, which is what made the
console look a decade older than it is.

The seventeen rail tabs moved from Unicode dingbats to inline SVG. That is
not only cosmetic: a dingbat is drawn by whichever font the OS falls back
to, so the rail's weight and optical size varied per machine, and two of
the seventeen (U+2751, U+25E9) have no coverage in the stock Windows UI
font and rendered as empty boxes.

### The theme contract is now enforced

`theme.css` has claimed since it was written that app.css names no colour
outside the token file. That claim was false, and the test it named as the
enforcer did not exist. Nine raw `rgba()` literals had accumulated in
app.css and twelve hard-coded hexes in app.js, four of them duplicating
tokens the theme already defined and nothing used.

The app.js case was the worse one. The canvas painters read a token and
fell back to a literal — `PAINT.surface2 || '#2D2030'` — and `cssVar()`
returns `''` for a token that does not resolve. `''` is falsy, so a renamed
token did not fail: it silently painted the PREVIOUS theme onto the canvas
while the DOM around it painted the new one.

`test_theme_contract.py` (18 tests) now checks all of it: no colour literal
in either file, no undefined token, no dead token, no radius outside the
scale, and the colour rules the theme file declares load-bearing.

### Contrast fixes, several of them real defects

- `--text-tertiary` carried real labels at 3.79:1 for the whole of the
  first cut. It is 4.52:1 and clears AA for the first time.
- `--danger` sat at 3.70:1 while being the colour that says a thing will be
  destroyed. Now 4.99:1.
- `.chip.conf-LOW` and `.st-none` set a dim colour AND inherited a dim
  opacity, compositing to 1.83:1 — a confidence label nobody could read.
  Confidence stays encoded as opacity; the floor moved to 0.58.
- Form controls had no boundary: `--hairline` measures 1.48:1 against the
  card a field sits on. A dedicated `--field-edge` measures 3.30:1. This
  cannot be fixed with a fill — the ground is near-black, so a recessed
  field reaches only 1.18:1 however dark it goes.
- `--artefact-finance` and `--alert` were 4.4 degrees apart, which violated
  the theme file's own stated rule that the two must not converge. Now 17.0.
- The seven node hues are held apart by CIEDE2000 rather than by eye: the
  closest pair went from 12.0 to 15.8.

### Responsive

Three media queries became ten, including the first height-axis rules in
the file. Every real failure in this layout was a height failure: the rail
is a column of seventeen tabs needing ~900px, and it used to `overflow:
hidden` and simply amputate the last few with no way to reach them.

The app bar no longer wraps its buttons onto two lines, and no longer
scrolls the page sideways. `#hdr-user` was 326px of that bar — a third of
it — because `/auth/me` returned a user_id and nothing else, so the pill
could only render a raw UUID. (`/auth/me` carries `display_name` and
`email` as of Alpha 4, and the bar now renders the name.)

### Also

- The read-path Postgres tests are gated on `DATABASE_URL` like every other
  `*_pg.py` file. Without one they errored in fixture setup rather than
  skipping, so a healthy local run ended `902 passed, 890 skipped, 11
  errors`.
- All sixteen console screenshots re-shot on the new UI, against the
  documented `OP-SHOWCASE-26` showcase seed. The **Analysis** pane is no
  longer the empty "Run analysis" prompt it had been in every previous
  release: brokerage, Burt constraint, effective size, communities and the
  key-player cut set are computed and shown.

## Alpha 2 — 2026-08-25

Second packaged release. **Still not audited, and still not lawful to
operate against real material until the five blocking items in
[docs/16](../docs/16-legal-and-external.md) are settled by somebody
outside this codebase.** No amount of code closes them.

### New

- **Analyst administration.** Creating an account used to require a shell
  on the server with `DATABASE_URL` and the TOTP key exported. There is
  now an **Admin** pane: create analysts with one-shot credentials, grant
  and revoke global roles, set clearance, deactivate (which revokes their
  sessions), unlock after failed logins, and re-issue a TOTP secret for
  the analyst whose phone is gone. Behind `user.manage` — SYS_ADMIN only,
  step-up enforced.
- **First-run setup in the browser.** A fresh install offers setup on the
  sign-in screen instead of demanding the CLI. The door is gated on the
  user table being empty, under an advisory lock, and closes permanently
  at the first account.
- **Phase 4's read path.** `collect.document` and `collect.watch_hit`
  were written by the collector from the day the phase landed and read by
  nothing. A watch could fire four hundred times and an analyst saw the
  integer. Feeds -> **Collected** now lists documents and watch hits,
  with acknowledgement.
- **Dual-control approvals have a surface.** Before this, a case with
  dual control on merges could not be merged from the browser at all: the
  endpoint demanded an `approval_request_id` nothing could produce.
- **Metric-history trend chart** (Analysis -> Trend), the last UI gap in
  Phase 3.
- **New theme.** Wine-shifted "Mulberry Nocturne" palette; tokens live in
  `theme.css` so a reskin never touches structure.
- `start.cmd` for double-click launching on Windows.

### Fixed

- **Every phase has now had an adversarial review** -- Phase 6 was the
  last. Nine findings, all closed, including `unmerge` writing recorded
  endpoints over an edge a later live merge owned (reversal is now
  LIFO-enforced), a dry-run purge that reported all-zero counts so the
  preview could not distinguish "nothing due" from "twelve exhibits about
  to be destroyed", and a refused approval whose audit row was rolled
  back by the transaction that refused it.
- **The audit chain had no anchor.** A forged "first row" passed every
  check and left `/audit/verify` answering INTACT. Now reported.
- **Break-glass no longer claims an elevation it does not perform.** It
  never raised effective clearance; the claim is withdrawn rather than
  implemented, because an analyst who believes it worked stops looking
  for another way in during the incident it exists for.
- Four analyst panes that reported a failure as a fact about the case,
  including co-participation rendering "undefined -- undefined" on every
  row under a fully green suite.

### Still not in it

- The five blocking legal items (docs/16 L1-L5). Sample handling and
  stealer-log data must not be switched on until they are settled.
- No security audit and no penetration test.
- XenForo / MyBB / Telegram collection adapters; document embeddings; a
  collection scheduler process.
- Fuzzy hashing, YARA and sandbox detonation. Each absence is recorded on
  the sample row with its reason.
- Deferred hardening: session IP/UA binding, RLS under a non-owner
  database role, DNS-rebinding-proof SSRF protection, login timing
  equalisation.
- WebAuthn -- deliberate; TOTP is the floor.
- CONCOR; the assumptions register.

### Verification at release

| | |
|---|---|
| Tests | 1891 passing, 0 failing, 0 skipped, across `apps/api/tests` and `packages/ontology` |
| Lint | ruff clean |
| Database | Alembic head 0055 |
| Adversarial passes | 9, each of which found a real defect |


## Alpha 1 — 2026-07-26

First packaged release. **Not audited; not lawful to operate against real
material until the four items in [README.md](README.md) are settled.**

### What is in it

Every phase has a service, a test suite, an HTTP API gated by the
five-part access check, an analyst pane, and at least one adversarial
review.

- **Graph and assertions** — nothing is written without a graded source.
- **Sociogram** with projections, ego networks, shortest path, and an
  as-of timeline. **Live**: another analyst's changes now arrive without a
  refresh.
- **Analytics** — centralities, Leiden communities, Burt constraint, cut
  vertices, key-player sets, signed balance. Computed over the projection
  and labelled as such.
- **Collection** — adapter interface, scheduler, persona vault, watch
  matching, and a proposal review gate.
- **Notification and egress** — one classification gate on every outbound
  path, quiet hours, digests, HMAC webhooks, and a delivery ledger that
  records refusals with their reason.
- **Tradecraft** — reversible entity merge, dual control, ACH, redacted
  report builder, retention and purge, break-glass with mandatory review.
- **Comms** — durable-identifier normalisation across 15 platforms,
  contact-block parsing, PGP verification with three outcome classes, and
  co-participation into the sociogram.
- **Samples** — separate-origin download, encrypted at rest, quarantine to
  RE queue, static triage with recorded gaps, and a detonation
  authorisation record.
- **Ingest** — write-only keys, raw-before-parse, category classification,
  triage scoring, near-duplicate folding, and a dead-letter queue.

### Notable in this release

- **Live change push.** Postgres `LISTEN`/`NOTIFY`, statement-level, so a
  400-row write wakes a client once. The socket carries **no case
  content** — it is a hint to refetch through the gated endpoints, which
  is why it needs no filtering logic of its own.
- **The Lab pane.** Invariant 10 as a screen: metadata renders, bytes
  never do. No preview, no hex view, no `innerHTML` and no iframe anywhere
  in it.
- **Detonation / VM panel.** Records an authorisation and submits nothing,
  with the consequence of each exposure level written next to it.
- **Deceptive-character defence.** Bidi overrides and zero-width
  characters are substituted before reaching the DOM, at the data
  boundary rather than at each of the two dozen sites a label is drawn.
- **A `?` keyboard map** and a request indicator covering every fetch.

### Known limitations

Documented rather than hidden. `docs/17-flagged-for-review.md` is the
full list.

- No third-party security audit.
- WebAuthn is not implemented; authentication is password + TOTP.
- Fuzzy hashing (imphash, ssdeep, TLSH), YARA matching and sandbox
  detonation are **not built**. Each absence is recorded on the sample row
  with its reason — a NULL imphash reads as "no imports", a recorded gap
  reads as "nobody looked".
- Deferred hardening: session IP/UA binding, RLS under a non-owner
  database role, DNS-rebinding-proof SSRF protection, login timing
  equalisation.
- Phase 6's adversarial review is partial: ACH has had one; merges,
  retention, approvals and break-glass have not.
- No collection scheduler process — collection runs when invoked.
- Metric history is not charted, and CONCOR is not implemented.

### Verification at release

| | |
|---|---|
| Tests | 1206 passing, 0 skipped, across `apps/api/tests` and `packages/ontology` |
| Lint | ruff clean |
| Database | Alembic head 0045 |
| Adversarial passes | 7, each of which found a real defect |
