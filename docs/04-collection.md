# 04 — Collection and the aggregation bucket

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
When a parser breaks you re-parse history instead of re-collecting it —
which matters when the original thread has since been deleted.

## Per-platform notes

### RSS / Atom
Easiest, still has traps. Use conditional GET (`ETag`, `If-Modified-Since`)
— polling without it will get you blocked from legitimate sources. Most
feeds truncate, so fetch the linked article and store both. Handle feeds
that reuse GUIDs on edit.

### XenForo
No usable API in practice. XenForo 2 ships a REST API but it is disabled by
default and no criminal forum enables it, so this is authenticated HTML
parsing against a session.

- Session cookies expire and rotate; detect the login redirect and
  re-authenticate rather than silently collecting login pages for a week
- Thread pagination is `/page-N`; last-page detection needs care
- Post IDs are stable, post *content* is editable — hash content, version
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

- **Bot API** — only sees chats the bot has been added to. Cannot read
  arbitrary channels. Fine for your own alerting, useless for monitoring.
- **MTProto user client** (Telethon / Pyrogram) — acts as a user account.
  This is what "watch channels" requires.

MTProto specifics:
- `FLOOD_WAIT_X` must be honoured exactly, with backoff. Ignoring it is the
  fastest way to lose an account.
- Session files are credentials. Encrypt at rest; treat loss as a breach.
- One session per persona, bound to one egress. Never share.
- Join events are visible to channel admins. Joining is an overt act with
  operational consequences — surface that in the UI before someone clicks.
- Numeric user ID is durable; `@username` is recycled. Store both, key on
  the ID.
- Channels get deleted. Mirror content promptly; you are often the only
  remaining copy.

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
- Decryption happens only in the collector process, only at use time.
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
- Human-plausible activity windows — a persona active 24/7 is a bot and
  reads as one.
- Status lifecycle: `HEALTHY → COOLDOWN → LOCKED → BURNED`. A burned
  persona is retired, never reused, and every document it collected is
  flagged for re-verification.

**Accountability**
Every `collection_run` records which persona and which egress was used.
This is not bureaucracy — if collection is ever challenged, "which account
gathered this, under what authority" is the first question, and it needs a
query rather than a memory.

## Parser drift

The most common silent failure in a platform like this: a forum upgrades,
the selectors stop matching, collection reports success and returns zero
items, and nobody notices for six weeks.

Defences, all of them:
1. **Structural assertions per parser** — expect ≥1 post block, a
   non-empty author, a parseable date. Zero valid items from a 200 OK is
   an alert, not a quiet success.
2. **Volume anomaly detection** — a source averaging 40 items/day
   returning 0 for two cycles alerts, even if parsing "succeeded."
3. **Login-wall detection** — classify the response before parsing.
4. **`parser_version` on every document**, so a re-parse campaign after a
   fix can target exactly the affected rows.
5. **Golden-file tests** — a saved HTML fixture per source, asserted
   against in CI.

## The aggregation bucket

Your "aggregation text bucket" is `collect.document` plus the object store.

**Three representations of every capture:**
1. **Raw bytes** — MinIO, WORM, object-locked, `sha256`. Never modified.
2. **Normalised text** — `document.body_text`. Quotes stripped, signatures
   removed, entities decoded, whitespace collapsed. What extractors read.
3. **Index** — Postgres FTS (`search_tsv`) + pgvector embedding for
   semantic and cross-lingual retrieval.

**Deduplication** on `content_sha256`. Same hash from the same source and
external ID is a no-op. Different hash, same external ID is an *edit* —
insert a new version, link `supersedes_id`, keep both. Edits and deletions
are themselves intelligence: a post deleted twenty minutes after appearing
is more interesting than one that stayed up.

**Retention** is per-source and per-case, enforced by a scheduled purge that
respects `legal_hold`. Documents supporting an accepted assertion are
pinned regardless of source retention, otherwise you retract the evidence
out from under your own graph.

## Triage queue

The bucket fills fast; without a triage surface it becomes a landfill.

`document.triage_state`: `NEW → TRIAGED → LINKED | DISCARDED`

The triage view should default to sorting by watch-hit priority and
extraction density — items containing several strong selectors first. Bulk
discard is essential. Cheap keyboard-driven actions (link to case, create
proposal, discard, escalate) are what make it survivable at volume.
