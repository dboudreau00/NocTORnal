# Changelog

## Unreleased

### Wave 2: the console holds no credential

The console kept the login-body token in page memory for exactly two paths
that could not read the cookie: the live websocket, which authenticated
from a token in its first frame, and the Lab download, which is
cross-origin so no `__Host-` cookie can reach it. Both are closed, and the
login response no longer carries a token at all.

**The websocket takes the cookie.** `ws.cookies` is readable on an upgrade
and the cookie value IS a session token, so `_handshake` prefers it and
keeps the first frame only for `scripts/bootstrap.py session`, which mints
in a shell and has no cookie jar. A browser cannot set a header on an
upgrade, so the CSRF double-submit is impossible there; `SameSite=strict`
plus an explicit `Origin` check refused before `accept()` is what stands in
its place. Measured in a browser: sign in, open a case, reload, reopen —
the dot stays live, `sessionStorage` and `localStorage` are both empty, and
the only cookie script can see is `__Host-csrf`.

**The Lab download is a one-shot ticket.** Minted on the application origin
under the cookie session, so the double-submit applies to the mint; stored
as a hash (migration 0061, `lab.download_ticket`); redeemed exactly once by
a single conditional `UPDATE`, so two simultaneous redemptions cannot both
win; sent in the POST body rather than a URL, because a URL reaches the
access log, the Referer and the history. Sixty seconds, because it is a
hand-off between two requests the browser makes back to back.

**Then the token went.** `POST /auth/login` answers 204 with the cookie
pair and nothing else. `deps.session_token` still accepts a Bearer, which
is how a script client and the `#token=` hand-off work; what is gone is
login handing one out. Twenty-seven test files that read the token from
that response now mint a session directly, the way `bootstrap.py` does.

**What the review caught, and it was not small.** Sign-in was completely
broken: `doLogin` still read `out.token` from a response that had become a
204, `_fetch` returns null for a 204, and every form sign-in threw, was
swallowed by the catch, and told the analyst "Unexpected error" while the
server had in fact signed them in and set the cookies. Three reviewers
found it independently. There is now a pure test that login answers 204
with no body, which nothing had covered.

Two security defects were closed after the first pass. The redemption
audited every failed presentation including one that matched no row — a
path reachable on the sample origin with no credential at all, writing into
an append-only hash-chained log — so an unknown ticket is now a sampled
warning and the route carries a named rate limit. And the redemption
re-checked the sample's labels but not the ACCOUNT, so inside the
sixty-second window a deactivated analyst still got the archive; it now
re-derives the account and the permission, and the residual is stated
exactly where it is bounded.

A third finding predates this wave: `/api/v1/live` is routable on a process
configured as the sample origin, because the middleware that makes that
process serve bytes and nothing else never runs for a websocket scope. The
upgrade is refused there now.

**A control that would have shipped silently broken.** The `Origin` check
compared only against the configured origin. The shipped launcher binds
`127.0.0.1:8000`, `NOCTORNAL_BASE_URL` keeps its matching default, the
console is opened at `localhost:8000` — two genuinely different origins,
correctly distinguished, and the result was that every live socket was
refused for every developer, before `accept()`, which reaches a browser
with neither code nor reason. It was found by opening the console, not by
reasoning. The rule now also accepts the origin the request arrived on,
which is the ordinary same-origin test, needs no configuration, and is not
weaker: a cross-site page cannot make `Origin` and `Host` agree.

**Known.** The one residual on the ticket is stated in `0061` and in
docs/17 F22: a ticket minted under a session revoked inside the following
sixty seconds can still be redeemed, by a holder whose account is still
active, still permitted, and for a sample they may still read. Separately,
and not introduced here: a `NOCTORNAL_TOTP_KEK` that does not match the one
an account was enrolled under makes `POST /auth/login` answer 500 rather
than refusing cleanly, and the `totp_kek_set` readiness check cannot see
it, because it verifies the key decodes and not that it decrypts anything.
Met while setting up the browser verification, and worth a refusal of its
own.

### Wave 1: it can be deployed as a service rather than run as a script

Until now the only way to run this was `scripts/launch.ps1` on a laptop:
one uvicorn process bound to loopback, the schema's owner as the database
role, the object store over plain HTTP, and a compose file whose first
line says not to derive a deployment from it. There was no Dockerfile in
the tree at all.

**`infra/production/` is the real one, and QUICKSTART now says so.** One
host, docker compose, no orchestrator. Caddy terminates TLS for the
application and the sample origin and is the only thing that publishes a
port; Postgres, Redis and MinIO are reachable only on the compose network.
A one-shot `migrate` job runs Alembic as the schema owner and everything
else waits for it. `infra/production/README.md` is the operator procedure,
including what this deployment still does not give you.

**The API no longer owns the tables it writes.** `noctornal_app` is
created at initdb -- the only place `CREATE ROLE` can live, since this
tree forbids the migration role from being a superuser -- and migration
0060 grants it. Verified against a running stack: the API connects as
`noctornal_app`, `core.node` is owned by `noctornal`, and
`ALTER TABLE audit.event DISABLE TRIGGER USER` comes back **"must be owner
of table event"**. That is the append-only audit and custody chain
defended by the database rather than by the application's good manners.

0060 is a complete no-op when the role is absent, because ten `*_pg` test
files need ownership to run `ALTER TABLE ... DISABLE TRIGGER`, and CI runs
both the upgrade and the downgrade round trip. CI creates the role by
running `db/init/10-app-role.sh` itself, so the ten new privilege tests run
there rather than skipping.

**A production process refuses to start on a development secret.**
`config.verify_environment()` reports every problem at once, each with what
it costs, and only when `NOCTORNAL_ENV=production` -- a laptop and CI are
untouched, which is why the check is still there in a week. Measured: a
container given `dev_only_change_me` in its DSN, `SMTP_ALLOW_PLAINTEXT`
and `NOCTORNAL_ENABLE_DOCS` names all three and does not boot.

**The readiness register now refuses a quiet green.** Four of the thirteen
checks are blocking, `report()` carries `blocking_failures`, and two things
consult it: `POST /collection/sources/{id}/run` answers 409, and so does
the unattended cron path. That second one was found by adversarial review
after the first had shipped in this same change -- a gate on the attended
route only would have let the cron poll real sources on a deployment whose
blockers were red, which is precisely the claim the tier is making. Two new
checks: `ingest_pepper_set` and `app_db_role_not_owner`.

**The sample origin is a compose service.** The same image, a second
process, its own hostname. Verified: `origin_split()` answers `app` on one
and `sample` on the other, from the server process's own environment.

**Things that run on a timer now run.** A `cron` service runs
`scripts/notify_drain.py` and the new `scripts/collection_poll.py`. The
collection runner respects each source's jittered `next_due_at` rather than
imposing a cadence -- docs/04 and docs/18 both name a scheduler on a
regular tick as an operational-security failure -- and a new per-source
advisory lock stops two runners corrupting one source.

**Known, and not fixed here.** No real SMTP relay exists on the build
machine, so "a priority-1 notification leaves the building" is the one line
in this wave that is wired and documented but unproven. (The next clause
said the websocket and the Lab download still authenticated from the
login-body token and that a reloaded session was not live. Wave 2 above
closed all three, and since this section is an unreleased note rather than
a dated record, correcting it is the point.) `docker exec` does not
inherit a variable exported
inside a container's entrypoint, which made two verification probes report
failures the deployment did not have -- both were the probe, and
`/proc/1/environ` is what to read instead.

## Alpha 5.2 — 2026-09-10

The b-revision of Alpha 5.1, closing what a re-read of it found. Alpha 5.1
wrote a linter for the previous review's examples; this closes the classes
those examples belonged to.

### The counters are generated, and the tolerance is gone

`test_doc_invariants` allowed a quoted test total to sit within five per
cent of the tree. At this size that is eighty tests of slack, and Alpha
5.1 shipped a README claiming 1627 against a tree of 1639 — stale, and
green, because the drift fitted inside the band. `scripts/refresh_counters.py`
now writes every live counter (tests, revisions, Alembic head, version,
completion) from the tree, the test asserts that running it would change
nothing, and the tolerance is zero. Same arrangement as `db/schema.sql`.

Two numbers that nothing can derive are gone rather than unchecked: the
"collected items" totals, which need a pytest collection, now live only in
these per-release entries, where they are dated records of one run.

### The invariant tables are held to each other

Alpha 5 reworded invariant 7 in CONVENTIONS and ARCHITECTURE — credentials
never leave the **vault**, which runs inside the API process, because there
is no collector. The README's table, the one a new reader meets first, went
on saying "never leave the collector, decrypted only in the worker process":
two processes this build does not have, on the front page, under a linter
that was looking for the removed `sigma.js`. All three statements of each
invariant are
now held to a distinguishing word, so a row reworded into something the
tree does not do fails whatever it was reworded to.

### Behaviour that was designed and never built

Auto-merge survived the Alpha 5 pass in the ontology definition, the
Telegram normaliser, the generated TypeScript, a comms test and the README,
all describing it in the present tense. A strong-selector collision raises
`StrongSelectorConflict` — a merge *lead* an analyst confirms. The register
that catches this now reads source and tests as well as prose, and carries
its maintenance rule: when a decision record says a thing was never built,
add it here.

### Smaller, same shape

- `retract_assertion`'s own docstring still said "history is superseded,
  not overwritten" above the stamp-in-place UPDATE that Alpha 5.1 decided
  was a marked row.
- `apps/api/pyproject.toml` described itself as "Session 3 lands
  authentication" — packaging metadata of a 0.5.1 release, in no linter.
- README claimed 59 revisions "all reversible". They are reversible on an
  EMPTY database, which is what the round-trip test proves; a downgrade
  past `0017` on a populated one is refused on purpose.
- README sold COMPLIANCE-mode WORM without saying the shipped compose file
  sets the bucket DEFAULT to `GOVERNANCE 365d`. The per-object COMPLIANCE
  lock `EvidenceStorage.put()` applies is the guarantee; the bucket default
  is the floor for anything written by another path.
- Three overall completion figures — 92.8%, ~92%, ~95% — are now one, and
  only `ROADMAP-REMAINING.md` works it out.

**Known.** The first run of `refresh_counters.py` rewrote two dated records
it walked past: "it had 673 passing tests" and "surveyed at revision 0052".
Both were restored, the shapes were narrowed to four-digit totals and the
`Alembic head` phrase, and the tool now prints every line it changes. A
generator loose in prose is a new way to lose history, and it is on the
first page of that script.

The Redis GCRA agreement test still fails on the development box every run
and passes on CI: clock drift between the WSL container and the host, and
the injected-clock refactor is still owed.

## Alpha 5.1 — 2026-09-09

Follow-up release. **Still not audited, and still not lawful to operate
against real material until the five blocking items in
[docs/16](../docs/16-legal-and-external.md) are settled by somebody
outside this codebase.** Eight items from the owner's review of Alpha 5,
each with a test that fails on the tree as it was:

- Body caps: `POST /samples` and `POST /cases/{id}/deception/emails` are
  enforced by `BodyCappedRoute` at the ASGI receive, like evidence. The
  routers' private chunked reads, which ran after the multipart parser
  had spooled the whole body, are gone.
- The CSRF double-submit compares in constant time (`hmac.compare_digest`
  over bytes; a non-ASCII header is a 403, not a TypeError).
- The login audit hashes the address the session is bound to
  (`client_ip`), not the proxy's.
- The command palette offers every pane the rail has, in rail order; a
  test holds the two together.
- Invariant 5 decided: a retraction is a marked row, stamped once, not a
  supersession; a test pins that nothing else on the row changes.
- One session story across QUICKSTART, ARCHITECTURE and SECURITY: the
  cookie is the session; the login-body token is an in-memory,
  login-lifetime capability for the websocket and the Lab download until
  those two paths accept the cookie.
- CONVENTIONS no longer claims an implemented auto-merge or cursor
  pagination, and counts 59 revisions. README refreshed (live CI badge,
  Canvas 2D, 1627 tests, 59 revisions, generated `db/schema.sql`) and now
  held by `test_doc_invariants.py` like every other document.

**Known.** CI on the release commit: 2273 passed, 0 skipped, on a fresh
database. On the development box the Redis GCRA agreement test
(`test_redis_and_python_agree_request_for_request`) fails at its usual
iteration 23 every run — clock drift between the WSL container and the
host, the injected-clock refactor still owed. The samples positive
control leaves one quarantined 64 KB `cap.bin` per full-suite run in a
reused database, because a submission writes to the append-only access
ledger and can never be deleted; the same residue policy as custody.

Not in this release, by decision: the cookie pair on the websocket and
the sample origin, a `key_id` that selects a KEK, a COMPLIANCE bucket
default, the Telegram bare-positive refusal, the confidence-threshold
alignment, RLS under a non-owner role, a collector process — and
nothing of L1–L5 in software.

## Alpha 5 — 2026-09-09

Review release. **Still not audited, and still not lawful to operate
against real material until the five blocking items in
[docs/16](../docs/16-legal-and-external.md) are settled by somebody
outside this codebase.** Nothing in this release touches those.

An external product review of Alpha 4 was accurate on every point checked.
Its recurring finding was this codebase's own signature defect: a
document, docstring or counter claiming something the code does not do.
This release answers its first two tiers.

### The documents describe the program that exists

Eight documents still described the July sketch, every piece of it removed
or never built: Next.js (removed), OpenFGA and SpiceDB (removed),
NATS and Celery (removed), three trust zones (superseded), a sigma.js
WebGL sociogram (replaced by Canvas 2D), UUIDv7 (not in the tree).
The tree has been one FastAPI process on Postgres 16 with a
vanilla console under a strict CSP, a Postgres access gate and a Canvas 2D
sociogram since August. Every live description now says so; every
reversed decision keeps its history with a dated superseded-by note; the
launch scripts no longer announce containers that do not exist; and a test
refuses any new mention of the removed stack unless the line marks it as
history. `README.md` is the owner's and was left alone.

The version is single-sourced from `pyproject.toml` (it said 0.1.0 while
the package said 0.4.0). `db/schema.sql` is generated from a migrated
database and diffed in CI — it had named five of eleven schemas under a
docstring calling it a mirror. Test and migration counts are dated
snapshots held to the tree by a test, and a document that quotes an
Alembic head must quote the real one.

### Before any second analyst

- **ACH cells can be scored from the console.** The stance route had
  existed since Phase 6 with nothing calling it. Each evidence × hypothesis
  cell opens a chooser showing the assertion's Admiralty grading and the
  five-point stance scale; the ranking re-renders on save.
- **Recovery codes can be typed.** The login field admitted six digits
  only, so the documented clock-skew fallback was a bootstrap script that
  bypasses MFA.
- **The console uses the cookie session.** `__Host-session` is HttpOnly
  with a readable CSRF half; nothing is written to web storage; logout's
  cookie deletions carry `Secure`, which browsers had been ignoring. A
  `#token=` link can no longer replace a session the browser already holds
  (it did, browser-wide, in the first cut of this change — caught by the
  adversarial review), and the server refuses to adopt a cookie for a
  different account with a 409 and an audit row. The websocket still
  authenticates from a token in its first frame, so a session restored
  from the cookie is honestly "not live" until the next sign-in, and says
  so.
- **Two `labelOf` functions became one.** The second silently shadowed
  the first, and projection-only nodes printed `null`.
- **Bodies are capped before they are buffered.** Evidence uploads had no
  cap at all onto a COMPLIANCE-locked bucket; ingest checked its cap after
  buffering the payload. Both now refuse with 413 before the bytes
  accumulate.
- **The dead-letter listing is scoped** to what the caller can read; it
  had listed every case's failures to any holder of global `ingest.read`.
- **The sample-origin check is decided by configuration, never by the
  Host header.** It had compared against `request.url`, which Starlette
  builds from a client-supplied header, and was unsatisfiable from a
  console whose CSP allowed only its own origin. Three variables and five
  verdicts now decide it; the UI CSP names the sample origin; unset means
  the control is OFF and every download refuses, in the readiness register
  and in every document that describes it. The sample origin is a second
  process of this code — a deployment decision recorded, not made.
- **The persona status write has a ceiling and checks its rowcount**; it
  had burned a RED persona for any holder of the global verb who knew the
  id, and returned 200 for an id that did not exist.
- **Credential-free websocket handshakes are refused before `accept()`**
  and bounded per peer. The first cut refused after accepting, which under
  uvicorn's websockets backend let a hostile peer hold the transport for
  ten seconds uncounted — measured, not reasoned, by the review that
  caught it.
- **Migration 0059 binds every compartment column, and the ingest key's
  forced compartment, to the registry.** A raw UPDATE or a psql typo can
  no longer file material under a compartment nobody registered. The
  migration refuses to run over legacy values and prints the cleanup.
  Eleven test fixtures and the demo seeder had been writing unregistered
  keys, several passing only because an earlier file left the key behind;
  each now registers what it writes.

### The hygiene checker was vacuous from a worktree

`scripts/check_source_hygiene.py` matched its skip list against absolute
path parts, so from any checkout under a `.claude/` directory it scanned
nothing and reported a clean tree. It now compares in-tree paths and
refuses an empty scan. It also fails the build on the owner's private
alias, which shipped on the licence page of three releases before this one.

### Known

The suite is not order-independent on a reused database (see Alpha 4).
`test_ratelimit_redis::test_redis_and_python_agree_request_for_request`
fails deterministically on the development box and has since July; its
docstring records the injected-clock refactor it needs.

Full suite on the release commit, both pytest roots, migration 0059:
**2255 passed, 3 failed** — that Redis flake, and the two version-contract
tests, which failed in the recording run because the version was bumped
while it ran and pass on the final tree.

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
