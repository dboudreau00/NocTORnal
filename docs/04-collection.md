# 04. Collection and the aggregation bucket

## Adapter contract

Every source kind implements one contract, `Adapter` in `collection.py`,
and is registered in one place, `default_adapters()`: `rss`, `xenforo`,
`mybb` (public boards), `xenforo_member` and `mybb_member` (a board read as
a signed-in member), and `telegram`. New platforms are new adapters, never
new pipeline code. The contract is declared attributes (`source_kinds`,
`requires_authority`, `persona_platform`, `keeps_raw`, page, byte and time
caps) and hooks that each have a no-op base: `refusal`, `validate_source`,
`validate_config`, `validate_persona`, `authority_need`, `plan` (before any
network), `fetch`, `commit`, `commit_item` and `settle`.

`fetch` returns `Item`s in a `FetchResult`, never a graph element: an
adapter holds nothing that could write `core.node` or `core.edge`
(invariant 3). `run_once` stores each item as a versioned `collect.document`
in its own savepoint, with its raw markup and retention clock, matches the
source's watches and writes a `collect.watch_hit`. No extractor and no
proposal runs in a poll; the only path from a source into `collect.proposal`
is a manual capture (Triage, Capture text).

Parsing is a pure function (`forum_parse.py`: bytes in, plain data out). The
adapters parse each page in a bounded child process that limits its own CPU
and memory, and in production that child runs in the isolated analysis
worker (docs/17 F42), so a page built to exhaust the parser costs at most its
wall clock and is reported as parser drift.

**Raw before parse.** An adapter that sets `keeps_raw` stores each item's own
markup, with navigation and form tokens removed, in the collect-raw bucket
(`collect.document.body_html_key`), inside the item's savepoint. When a
parser breaks, the markup is there to re-run it over instead of
re-collecting, which matters when the original thread has since been
deleted. If the object store is not configured or refuses the put, the
document is kept and the run is PARTIAL with `RAW_NOT_KEPT`. Nothing
re-parses stored markup by itself.

## Per-platform notes

### RSS / Atom
Easiest, still has traps. Conditional GET is used, because polling without
it gets you blocked from legitimate sources: the stored `ETag` goes back as
`If-None-Match` (`Last-Modified` is recorded and not sent back). Most feeds
truncate; the adapter stores what the feed carries and does not
fetch the linked article. A feed that reuses a GUID on edit becomes a new
version of the same item. The feed is parsed with the standard-library XML
parser and entity resolution disabled: a feed is by definition
attacker-adjacent.

### XenForo
No usable API in practice. XenForo 2 ships a REST API but it is disabled by
default and no criminal forum enables it, so this is HTML parsing, as a
public reader or as a signed-in member.

- Session cookies expire and rotate. A public read that meets a login page
  stops as a FAILED run and stores nothing (a `LoginWall`); a member read
  signs in again once when the board ends its session, and a second loss ends
  the run where it was.
- Thread pagination is `/page-N`; last-page detection needs care. The page
  number stored is the one the fetched page says it is, and the walk moves one
  page past the last page it read.
- Post IDs are stable, post *content* is editable: content is hashed, a
  change is a new version, old versions are kept.
- Quoted blocks (`<blockquote>`) are cut out before selector extraction and
  only the quoted post ids are kept, or you attribute every quoted address to
  whoever quoted it. This one mistake will pollute a case faster than
  anything else.
- Signature blocks likewise: the same Jabber address on 4,000 posts creates
  4,000 false observations. A signature is kept once per post beside the
  post (`collect.forum_post`), as intelligence about the author.
- "Thanks/likes" are cheap edges but genuinely informative for affiliation;
  the parser reads the reaction types and up to 50 reactor names per post.

### MyBB / phpBB
MyBB is built; phpBB has no adapter. Older, simpler markup, more fragile.
Same quote-stripping requirement. `showthread.php?tid=` style URLs; the
adapter always asks for `mode=linear`, because the threaded view returns a
different DOM. MyBB prints the board's own zone with no offset, so a post time
is stored only when the source declares both the zone and the formats.

### Telegram
Two entirely different paths, and the choice matters:

- **Bot API**, only sees chats the bot has been added to. Cannot read
  arbitrary channels. Fine for your own alerting, useless for monitoring.
- **MTProto user client** (Telethon / Pyrogram), acts as a user account.
  This is what "watch channels" requires, and what is built.

MTProto specifics:
- `FLOOD_WAIT_X` must be honoured exactly, with backoff. Ignoring it is the
  fastest way to lose an account.
- Session files are credentials. Encrypt at rest; treat loss as a breach.
- One session per persona, bound to one egress. Never share.
- Join events are visible to channel admins. Joining is an overt act with
  operational consequences, surface that in the UI before someone clicks.
- Numeric user ID is durable; `@username` is recycled. Store both, key on
  the ID.
- Channels get deleted. Mirror content promptly; you are often the only
  remaining copy.

**What is built (F5.2 to F5.4).** The MTProto user client (Telethon 1.45 or
later in the 1.x line, the optional `telegram` extra) reads channels,
supergroups and basic groups as a persona. Without the extra, every
Telegram act refuses with one sentence and the `telegram_collection`
readiness row names the gap.

- *One persona, one account, one exit, for life.* A Telegram persona names
  an egress profile when it is created, keeps it for good, and no other
  Telegram persona may ever hold it, a burnt one included: Telegram links
  accounts that were seen from one address (a unique index holds it). Its
  account id (`u:<id>`) is set once at enrolment; a different account is a
  different persona. It is registered on no venue: it reads each chat through
  the chat's own source.
- *Enrolment on the server, never in the browser.* The console creates the
  persona with its device (model, system version, app version, language
  codes: what Telegram is told instead of this server's platform string)
  and no credential. An operator with a shell runs
  `python scripts/telegram_persona.py enrol --persona <id>`, signs in with
  their email, password and a current authenticator code (a recovery code
  and an administrator-issued password are refused), and types the
  persona's api_id, phone number, api_hash, the login code and any two-step
  password. The session is sealed in the persona's credential column like
  every other persona credential; neither the phone number nor the
  two-step password is stored. `import` reads a session from standard
  input; `logout --reason ...` logs the session out at Telegram and
  destroys the credential. A persona Telegram locked is logged out (with
  `--local-only` when Telegram no longer answers for it) and enrolled
  again.
- *The only way out is the egress proxy.* Every connection, a poll, an
  attended act or the script, leaves through the persona's route on the
  egress proxy as SOCKS5 with the route's credentials. A direct connection
  is refused in every environment, development included: it would show
  Telegram this server's own address. The client refuses, before any
  socket exists, an address outside Telegram's published IPv4 networks, a
  port other than 443, 80 or 5222, or any proxy but the persona's route.
- *A chat is looked up as its persona.* A chat is added from Feeds,
  Sources, Telegram chats, as @name, t.me/name or its id (c:<id>, g:<id>
  or the Bot API -100<id>). Telegram records that the account looked it
  up. An invite link is never followed: join a private chat from the
  persona's own device, then add it by its id. Adding by id reads up to 500
  entries of the persona's own conversation list; everything but the
  matched chat is dropped in memory and never logged or stored.
- *How it is read decides its provenance.* A chat read without joining is
  OPEN_GROUP and needs the persona's public authority; a chat read as a
  member is PERSONA_PARTY and needs a member authority. A public chat can
  be marked as a member chat, never back. The mark takes the persona's lock
  first, reads the chat again under it, and runs the membership check it
  queues under the same lock, so a persona that is busy refuses the whole
  act with nothing marked, and the retry starts clean. Joining is its own
  act, behind a fresh second factor and an explicit acknowledgement that the
  chat's administrators see it. A membership check reads the persona's own
  view of the chat and never joins.
- *What a poll reads.* The newest 200 messages on a first poll, then up to
  500 a poll oldest first from the last message read, then a recheck of up
  to 100 messages captured in the last 48 hours: one gone is marked deleted
  upstream (once, never cleared, the body kept) and one edited is a new
  version. Basic-group message ids are per account, so their documents
  carry the reading account and a rebind restarts from the new account's
  newest messages. Service messages are stored as fixed sentences. Media is
  never downloaded. A message whose sender cannot be typed is skipped by
  id and read past. A slow chat stops at its session's budget and carries
  on at the next poll.
- *FLOOD_WAIT and a lost session are the persona's.* Telegram's wait puts
  the persona on a machine hold for the asked time plus a margin; a
  revoked, banned, other-account or duplicated session locks it (a
  duplicated one also alerts the security officers); a session that does
  not answer in time rests the persona for 15 minutes so no second
  connection with the same key starts beside it. Each is recorded before
  the persona is unlocked, for a poll and for an attended act alike.
- *What leaves the host.* The persona's encrypted MTProto session to
  Telegram's data centres, through the egress proxy and its exit, carrying
  chat ids, access hashes and message ids. Never case data, never a watch
  term or a selector: nothing searches, nothing is marked read, nothing is
  sent, and matching happens here after the messages arrive.
- *The exposure switch.* `NOCTORNAL_TELEGRAM_SOURCE_CEILING` (CLEAR, GREEN
  or AMBER) is the highest label a Telegram source may carry and still be
  read. Unset means Telegram collection is off. AMBER_STRICT and RED never
  leave this platform, whatever the variable says; work at those labels is
  collected by hand into its case.
- *Retention.* Telegram documents take the CHAT_EXPORT rule's clock from
  their capture time. A document cited by a case under legal hold, through
  any version, is never purged; a purged one loses the typed ids and names
  its capture record held. The sweep that destroys collected documents past
  their clock is described under Retention below.

### General hygiene
- Randomised intervals with jitter, never a clean cron cadence: `next_due_at`
  adds symmetric jitter as a percentage of the interval, and a source that has
  never been polled is due now. `scripts/collection_poll.py` is a cron entry
  that asks `due_sources()` what is ready and polls that; the operator
  chooses how often to look and each source's own `next_due_at` decides when
  it is polled. A pass begins by marking the runs an earlier pass left
  RUNNING because its process was stopped where Python could not finish them
  (the collector sends the poll child SIGTERM): each is FAILED with the class
  Interrupted, only when no runner holds its source's lock, counted as
  `interrupted` and not as the source failing, and the source, whose schedule
  was never rolled, is polled again in the same pass. A dry run marks
  nothing.
- Per-source `max_rps`, spaced rather than bursted, from
  `collect.source.last_request_at`, which survives the process and is shared
  between workers. It is held in Postgres, not Redis.
- Backoff ladder on a challenge or a 429: the next poll waits twice the
  interval after one in a row, four times after two, up to a day. A forum is
  paced as a whole, not per source: two sources on one forum are never polled
  at once.
- Full request metadata retained for the custody record (the run's request
  log).

## Collection accounts (personas)

A watch link with account access is a credential management problem with an
operational-security problem wrapped around it.

**Credential handling**
- Envelope encryption: AES-256-GCM under `NOCTORNAL_PERSONA_KEK`, a key of
  its own that is never in the database. Ciphertext in
  `collection_account.secret_ciphertext`. There is no KMS or Vault in the
  product (infra/production/README.md).
- Decryption happens only inside `PersonaVault.use()`, only at use time, in
  the collector process in production (`scripts/collector.py`, which queues
  persona acts through `collect.persona_act`; docs/05, Persona credentials).
  Development runs the same code inline in the API
  (`NOCTORNAL_COLLECTOR_INLINE`).
- The API never returns plaintext. `collection_account.reveal` is registered
  as a step-up permission and nothing spends it: no route reveals a
  credential, deliberately (docs/05, Never revealed).
- `secret_rotated_at` is stamped when a credential is set or replaced (a
  platform moving a session is not a rotation) and returned with the persona.
  Nothing reminds anyone to rotate.

**Operational separation**
- One persona ↔ one egress profile. Enforced, not advised: a unique index
  for Telegram personas, and for every other kind `check_egress_separation()`,
  the persona gate and the egress proxy, which require the persona to be
  usable and alone on its profile. It is not a plain database constraint,
  because a profile legitimately serves different personas on different
  sources over time; what must not happen is two personas live on one profile
  against the same source at once. Two personas sharing an exit IP can be
  correlated by any competent forum admin, and you lose both at once.
- Consistent browser fingerprint per persona, stored in
  `fingerprint_profile`.
- Human-plausible activity windows (`active_window_utc` in the fingerprint),
  a persona active 24/7 is a bot and reads as one.
- Status lifecycle: `HEALTHY → COOLDOWN → LOCKED → BURNED`. BURNED is
  terminal and takes a reason, which is what stops the next analyst quietly
  reusing it: a burned persona is retired, never reused. Its documents are
  not flagged automatically; the run records the persona, so a query finds
  them.

**Accountability**
Every `collection_run` records which persona and which egress was used.
This is not bureaucracy, if collection is ever challenged, "which account
gathered this, under what authority" is the first question, and it needs a
query rather than a memory. A forum or Telegram source also needs a
collection authority a second person confirmed, and a declared
classification ceiling, before it is read (docs/00 decision 69).

**Where a poll leaves (egress proxy)**
Every poll takes its route from `egress.route_for` with its run as context.
In production that route is a tunnel through the egress proxy, which decides
from the database, never from the caller, whether the run, the persona, the
profile and the collection authority still allow this destination
(docs/20 section 8.5). It closes an open tunnel within 30 seconds of any of
them ending. An act (an enrolment, a join) is judged the same way target by
target; a stop (a logout) needs only the binding, and is limited to 60
seconds, 256 KiB and four an hour per persona. Every connection, allowed or
refused, is a row in the append-only connection ledger
(`collect.egress_connection`), labelled by its source's current
classification and compartments.

## Parser drift

The most common silent failure in a platform like this: a forum upgrades,
the selectors stop matching, collection reports success and returns zero
items, and nobody notices for six weeks.

Defences:
1. **Structural assertions per parser**, built for the forum parsers. A thread
   page with no recognisable post, posts whose ids are not read, most posts
   with no author or no time, a board page with no thread listing and a member
   page with no member are each reported as `PARSER_DRIFT` (the run is
   PARTIAL, the cursor is held so the next poll starts where this one did, and
   no deletion is reported). Zero valid items from a 200 OK is an alert, not a
   quiet success.
2. **Source health from consecutive failures.** A parser that broke this
   morning fails every time, so the signal is the streak: two in a row read
   DEGRADED and five read BROKEN, and the source goes on the unhealthy list.
   There is no volume anomaly detection (a source averaging 40 items a day
   returning 0 for two cycles, with parsing "succeeded"): it is not built.
3. **Login-wall detection**, the response is classified before anything is
   stored. A page that asks for a sign-in is a FAILED run.
4. **`parser_version` on every run**, so a re-parse campaign after a fix can
   target exactly the affected rows through `collect.document.collection_run_id`.
5. **Golden-file tests**, a saved HTML fixture per source kind
   (`apps/api/tests/fixtures/xenforo`, `mybb`, `telegram`), asserted against
   in CI.

## The aggregation bucket

The aggregation text bucket is `collect.document` plus the object store.

**Three representations of every capture:**
1. **Raw bytes**, MinIO, WORM, object-locked, `sha256`. Never modified.
2. **Normalised text**, `document.body_text`. Quotes stripped, signatures
   removed, entities decoded, whitespace collapsed. What extractors read.
3. **Index**, Postgres FTS (`search_tsv`) + pgvector similarity vectors
   (`collect.document_embedding`): similar wording from the built-in
   embedder on this host, which also meets a passage written in another
   alphabet or transliteration scheme, and similar meaning from an
   operator's model endpoint when one is configured. Victim data is never
   embedded.

**Deduplication** on `content_sha256`. Same hash from the same source and
external ID is a no-op. Different hash, same external ID is an *edit*,
insert a new version, link `supersedes_id`, keep both. Edits and deletions
are themselves intelligence: a post deleted twenty minutes after appearing
is more interesting than one that stayed up.

**Labels.** A document carries a classification and `compartments`
(migration 0070). Every read of one checks both, and its source's
classification (docs/05, "Collected documents carry compartments"). A
document is not a case's, so its labels are set where it is stored:

- *A capture* (Triage, Capture text) is stored at the label asked for,
  never below its case's, and under its case's compartments. A re-paste
  of the same text dedupes onto an earlier capture only under the
  identical compartments and only while that capture is unpurged, so text
  pasted into a compartmented case and into an open one are two documents
  with two locks. A case carrying a compartment an ingest feed forces for
  third-party personal data takes no capture: a captured document is in
  the free-text index, which decision 52 keeps away from victim personal
  data, and docs/16 L2 (how such data is minimised) is unsettled. Its
  material goes in as evidence, which is read only inside the case.
- *A collected document* (an adapter's) carries no compartment until its
  source does; the forum work that gives a source compartments owns the
  copy onto its documents.

Captures made before 0070 were labelled from the cases that cite them
(0071): the keys every citing case holds, and never below the least citing
case's classification. One that no lock fits (cited by cases with no key in
common, or by an open case) is counted by the readiness row
`captured_documents_compartmented` and listed by
`python scripts/legacy_records.py --section captures`.

`document_tsv` rebuilds the text index only when indexed text changes
(title, author handle, body, or a purge, which empties it), so a triage
click, a relabel or a compartment rename does not re-index a body of up
to 500 KB. A change that adds a column to the index adds it to that
trigger's column list.

**Retention** is per-source and per-case and respects `legal_hold`.
Documents supporting an accepted assertion are pinned regardless of source
retention, otherwise you retract the evidence out from under your own graph.
Nothing destroys a collected document by itself: it belongs to no case, so
the console's case purge never reaches it, and `scripts/retention_sweep.py`
sweeps those past their clock when an operator runs it, dry by default, under
a declared authority (infra/production/README.md, Retention sweep; docs/17
F30). Nothing schedules it, because it destroys third-party personal data.

## Triage queue

The bucket fills fast; without a triage surface it becomes a landfill.

`document.triage_state`: `NEW → TRIAGED → LINKED | DISCARDED`

The list is newest first (posting time, else capture time) and filters by
source, triage state and date. An analyst sets the state one document at a
time, behind the same label checks as a read. LINKED is set by hand, because
nothing automated links a document to the graph. Not built: a sort by
watch-hit priority and extraction density (items containing several strong
selectors first), and a bulk discard, both of which a high volume will want.

## Watches

A watch is a standing tasking against one source: keywords, selectors and
patterns, and the case it reports to. The collector matches each collected
item against its source's active watches inside the item's own savepoint and
writes a hit that carries its reasons (`matched_on`, a list), never a bare
score.

**What a reason says.** `keyword:<term>`, `selector:<term>` and
`regex:<pattern>` are the watch's own term found in the item's text (title and
body). `author:<id>` and `<label>:<id>` (a forward, a via-bot) are a selector
equal to a typed id the item carries. A forum post's signature is kept beside
the post and not in its text (`collect.forum_post`), and is matched on its own:
`signature_keyword:`, `signature_selector:` and `signature_regex:` say the term
was found in the signature. A signature is repeated on every post its author
writes, so a term in it raises a hit on each of those posts (the watch's
suppression window thins them by thread), and the reason is what tells an
analyst it is the author's signature that carries the term and not the post.

**A Telegram chat as the target (F47).** A watch of target kind
`TELEGRAM_CHAT` names its chat in `target_ref` by the typed durable id, `c:<id>`
or `g:<id>`, never an `@username` (a username is recycled, invariant 9;
migration 0130 holds the reference to that shape for this kind and no other).
It fires only on a message collected from that chat, and its reasons begin
`chat:<id>`. With no keyword, selector or pattern at all it fires on every
message of that chat: the default suppression window collapses those to one hit
per chat or topic an hour, and a window of 0 gives one per message. With terms
it fires on the messages that carry one, and still says which chat. A chat
watch that names a chat the source does not read, or sits on a source that is
not a Telegram chat, matches nothing, and the run reports it once as a watch
warning (PARTIAL), the way it reports a pattern that will not compile. Every
other target kind keeps the free text it had, and a watch of any other kind with
no term matches nothing.

**Making one (F53).** The Collected tab of the Feeds pane lists a case's
watches and, for a collection manager, adds one.
`POST /cases/{case_id}/collection/watches` takes the source, a name, what it
looks at (`BOARD`, `THREAD`, `USER`, `CHANNEL`, `FEED`, `SEARCH` or
`TELEGRAM_CHAT`), keywords, selectors and patterns, a priority from 1 (most
urgent) to 5, and the time within which further matches on one thread add no
hit. It needs the global `watch.manage` (which only the collection manager's
role holds) and the case's own gate with `collection.read`, and a closed case
takes no new watch. `GET /cases/{case_id}/collection/watches` lists the case's
watches behind `collection.read` and says whether the caller may add one. The
writer refuses, in a sentence: a source the caller cannot see (a 404, the one
a random id gets, so a watch goes only on a source its creator may read); a
kind outside the list; a watch of any kind but a Telegram chat with no
keyword, selector or pattern, which would match nothing and read as quiet; a
pattern that does not parse (it is parsed there and never matched there); and
a name the case already holds (a 409). A
Telegram chat watch names the chat by its typed id and must name the one its
source reads, so it cannot be aimed at a chat that never fires; with no term it
fires on every message of that chat. For every other kind the reference is a
note for the people reading the list: the collector reads the source's own
address and does not visit it. A watch applies from the next poll, and
documents already collected are not matched again. Each is audited as
`WATCH_CREATED` with the counts of its terms and never the terms, because the
audit trail is read by people with no access to the case's content. Stopping or
editing a watch is not built: only its creation is.

**Where it runs.** `collect.watch` and `collect.watch_hit` are under row-level
security (0124). The poll, a manual run and a pasted capture read the watches
and write the hits as the COLLECTION system purpose, which sees every case's
watches; the watch list and the route that makes a watch, and the hit listing
and its verbs, are the only users of them on the request connection, and they
are scoped to the case. A purge of a document keeps a
hit's reasons that are the watch's own configuration (its terms and the chat it
names) and replaces what was read from the document (an author or forward id)
with `[purged]`.
