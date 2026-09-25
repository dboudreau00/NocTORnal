# 04. Collection and the aggregation bucket

## Adapter contract

Every source kind implements the same interface. New platforms are new
adapters, never new pipeline code.

```python
class SourceAdapter(Protocol):
    kind: SourceKind
    parser_version: str

    async def discover(self, watch: Watch, ctx: RunContext) -> list[TargetRef]:
        """Enumerate what to fetch. Boards → threads, channels → messages."""

    async def fetch(self, target: TargetRef, ctx: RunContext) -> RawCapture:
        """Retrieve bytes. Honour conditional GET. Never parse here."""

    def parse(self, raw: RawCapture) -> list[ParsedItem]:
        """Bytes → structured items. Pure function, unit-testable offline."""

    def health_check(self, raw: RawCapture) -> HealthVerdict:
        """Did the page look like we expect? See parser drift below."""
```

`fetch` and `parse` are separated so raw captures are stored before parsing.
When a parser breaks you re-parse history instead of re-collecting it,
which matters when the original thread has since been deleted.

## Per-platform notes

### RSS / Atom
Easiest, still has traps. Use conditional GET (`ETag`, `If-Modified-Since`),
polling without it will get you blocked from legitimate sources. Most
feeds truncate, so fetch the linked article and store both. Handle feeds
that reuse GUIDs on edit.

### XenForo
No usable API in practice. XenForo 2 ships a REST API but it is disabled by
default and no criminal forum enables it, so this is authenticated HTML
parsing against a session.

- Session cookies expire and rotate; detect the login redirect and
  re-authenticate rather than silently collecting login pages for a week
- Thread pagination is `/page-N`; last-page detection needs care
- Post IDs are stable, post *content* is editable, hash content, version
  on change, keep old versions
- Quoted blocks (`<blockquote>`) must be stripped before selector
  extraction or you attribute every quoted address to whoever quoted it.
  This one mistake will pollute a case faster than anything else.
- Signature blocks likewise: same Jabber address on 4,000 posts creates
  4,000 false observations
- "Thanks/likes" are cheap edges but genuinely informative for affiliation

### MyBB / phpBB
Older, simpler markup, more fragile. Same quote-stripping requirement.
`showthread.php?tid=` style URLs; watch for both `mode=linear` and threaded
views returning different DOM.

### Telegram
Two entirely different paths, and the choice matters:

- **Bot API**, only sees chats the bot has been added to. Cannot read
  arbitrary channels. Fine for your own alerting, useless for monitoring.
- **MTProto user client** (Telethon / Pyrogram), acts as a user account.
  This is what "watch channels" requires.

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

**What is built (roadmap F5.2 to F5.4, 2026-09-24).** The MTProto user
client (Telethon 1.45, the optional `telegram` extra) reads channels,
supergroups and basic groups as a persona. Without the extra, every
Telegram act refuses with one sentence and the `telegram_collection`
readiness row names the gap.

- *One persona, one account, one exit, for life.* A Telegram persona names
  an egress profile when it is created, keeps it for good, and no other
  Telegram persona may ever hold it, a burnt one included: Telegram links
  accounts that were seen from one address. Its account id (`u:<id>`) is
  set once at enrolment; a different account is a different persona. It is
  registered on no venue: it reads each chat through the chat's own source.
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
  be marked as a member chat, never back. Joining is its own act, behind a
  fresh second factor and an explicit acknowledgement that the chat's
  administrators see it. A membership check reads the persona's own view
  of the chat and never joins.
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
  its capture record held. No route or script sweeps collected documents
  on its own (docs/17).

### General hygiene
- Randomised intervals with jitter, never a clean cron cadence
- Per-source `max_rps`, globally enforced through Redis
- Backoff ladder on 429/403, then automatic cooldown of the persona
- Full request/response metadata retained for the custody record

## Collection accounts (personas)

You asked for "watch links with account access." That is a credential
management problem with an operational-security problem wrapped around it.

**Credential handling**
- Envelope encryption: AES-256-GCM data key, wrapped by a KMS/Vault master
  key. Ciphertext in `collection_account.secret_ciphertext`, master key
  never in the database.
- Decryption happens only inside `PersonaVault.use()`, only at use time.
  That is in the API process: there is no separate collector process.
- The API never returns plaintext. `collection_account.reveal` exists as a
  permission but requires step-up *and* dual control, and fires a
  high-priority audit alert.
- Rotation reminders; `secret_rotated_at` surfaced in the admin view.

**Operational separation**
- One persona ↔ one egress profile. Enforced with a constraint, not a
  convention. Two personas sharing an exit IP can be correlated by any
  competent forum admin, and you lose both at once.
- Consistent browser fingerprint per persona, stored in
  `fingerprint_profile`.
- Human-plausible activity windows, a persona active 24/7 is a bot and
  reads as one.
- Status lifecycle: `HEALTHY → COOLDOWN → LOCKED → BURNED`. A burned
  persona is retired, never reused, and every document it collected is
  flagged for re-verification.

**Accountability**
Every `collection_run` records which persona and which egress was used.
This is not bureaucracy, if collection is ever challenged, "which account
gathered this, under what authority" is the first question, and it needs a
query rather than a memory.

**Where a poll leaves (egress proxy)**
Every poll takes its route from `egress.route_for` with its run as context.
In production that route is a tunnel through the egress proxy, and the proxy
checks, from the database and never from the caller: that the run is
running; that the persona is bound to the profile, usable and alone on it;
that the run's collection authority is live, covers the source at its
current address, and was recorded and confirmed after the profile last
widened and after the persona (or a persona-less source) was last re-bound;
and that the destination is the source's own site. It closes an open
tunnel within 30 seconds of any of these ending. An act (an enrolment, a
join) is judged the same way target by target: it reaches a source's site
only through that source's own passing target. A stop (a logout) needs only
the binding, and is limited to 60 seconds, 256 KiB and four an hour per
persona. Every connection, allowed or refused, is a row in the append-only
connection ledger (`collect.egress_connection`), labelled by its source's
current classification and compartments.

## Parser drift

The most common silent failure in a platform like this: a forum upgrades,
the selectors stop matching, collection reports success and returns zero
items, and nobody notices for six weeks.

Defences, all of them:
1. **Structural assertions per parser**, expect ≥1 post block, a
   non-empty author, a parseable date. Zero valid items from a 200 OK is
   an alert, not a quiet success.
2. **Volume anomaly detection**, a source averaging 40 items/day
   returning 0 for two cycles alerts, even if parsing "succeeded."
3. **Login-wall detection**, classify the response before parsing.
4. **`parser_version` on every document**, so a re-parse campaign after a
   fix can target exactly the affected rows.
5. **Golden-file tests**, a saved HTML fixture per source, asserted
   against in CI.

## The aggregation bucket

Your "aggregation text bucket" is `collect.document` plus the object store.

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

**Labels.** A document carries a classification and, since 2026-09-24,
`compartments` (migration 0070). Every read of one checks both, and its
source's classification (docs/05, "Collected documents carry
compartments"). A document is not a case's, so its labels are set where it
is stored:

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

Captures made before 2026-09-24 were labelled from the cases that cite
them (0071): the keys every citing case holds, and never below the least
citing case's classification. One that no lock fits (cited by cases with
no key in common, or by an open case) is counted by the readiness row
`captured_documents_compartmented` and listed by
`python scripts/legacy_records.py --section captures`.

`document_tsv` rebuilds the text index only when indexed text changes
(title, author handle, body, or a purge, which empties it), so a triage
click, a relabel or a compartment rename no longer re-indexes a body of up
to 500 KB. A change that adds a column to the index adds it to that
trigger's column list.

**Retention** is per-source and per-case, enforced by a scheduled purge that
respects `legal_hold`. Documents supporting an accepted assertion are
pinned regardless of source retention, otherwise you retract the evidence
out from under your own graph.

## Triage queue

The bucket fills fast; without a triage surface it becomes a landfill.

`document.triage_state`: `NEW → TRIAGED → LINKED | DISCARDED`

The triage view should default to sorting by watch-hit priority and
extraction density, items containing several strong selectors first. Bulk
discard is essential. Cheap keyboard-driven actions (link to case, create
proposal, discard, escalate) are what make it survivable at volume.
