# 12. Ingest API keys and feed categorisation

**Status: BUILT** (Phase 9, migrations 0033 onward). This document is the
domain reasoning; `ARCHITECTURE.md` describes what was built.

Two distinct things share the word "key" and should not share an
implementation:

- **Inbound keys** (`sk_`), machines push data *into* NocTORnal
- **Outbound credentials**, NocTORnal pulls *from* third-party APIs

Different threat models. Inbound keys are held by parties you do not
control and will leak. Outbound credentials are yours to protect and sit
in a vault of their own (Part 3).

---

## Part 1: Inbound ingest keys

### Key format

```
noct_sk_live_7Kq2vN8mPx4RtY6wZ3aB5cD9eF1gH0jL
└┬┘ └┬┘ └┬─┘ └──────────── 32 chars base62 ──┘
 │   │   └── environment: live | test
 │   └────── secret key
 └────────── vendor prefix
```

The prefix is not cosmetic. A fixed, searchable prefix means:
- leaked keys are findable in GitHub, pastes and your own logs
- you can register the pattern with GitHub secret scanning (the product does
  not do this for you)
- log redaction can match reliably rather than heuristically

### Storage

Split the key: a public `key_id` and a secret.

```
noct_sk_live_<key_id:8><secret:24>
            └── indexed ┘└─ HMAC-SHA256'd with a pepper ─┘
```

Look up by `key_id`, then constant-time compare the HMAC of the presented
secret. Do **not** bcrypt/Argon2 the whole key, a per-request KDF at
ingest volume will melt the API, and you cannot index a slow hash so you
would be scanning the table on every request.

Argon2 is correct for user passwords. HMAC with a pepper is correct for
machine keys. The difference is that machine keys are high-entropy by
construction, so the slow-hash defence against guessing is unnecessary.
The pepper is `NOCTORNAL_INGEST_PEPPER`, a secret of its own, separate from
the TOTP key so that an ingest key compromise and a TOTP secret compromise
do not share a blast radius; with none set, no key can be issued or
verified.

### Key properties

Every key carries:

| Property | Why |
|---|---|
| **Scopes** | `ingest:write` (and `ingest:status`) only, held by a CHECK that refuses `case:read`. **An ingest key must never be able to read.** A leaked write-only key means junk data; a leaked read key means the case file (invariant 11) |
| **Bound source** | One key ↔ one logical feed, so provenance is unambiguous |
| **Declared category** | The kind of feed this key sends (`declared_category`, one of the categories below); structure refines it |
| **Default grading** | Admiralty reliability applied to everything from this feed |
| **Classification ceiling** | Nothing from this key may be marked above X |
| **Forced compartment** | An optional compartment every record from this key carries |
| **IP allowlist** | CIDRs, compared against the address the server sees on the connection and never one a header supplies. Cheap and effective |
| **Rate + size limits** | A request is capped at the key's `max_bytes_per_request` (32 MiB unless set at issue), refused with a 413 before the body is read; a submission rate limit of 600 an hour per key, burst 120, enforced in Redis, fails closed when Redis is down |
| **Expiry** | Mandatory. Default 90 days, at most 365, no "never" option |
| **Owner** | A named human, not a team. Orphaned keys are how ingest paths outlive their purpose |

An unknown, revoked or expired key, or an address outside the allowlist,
gets one answer: 401 "invalid ingest key".

### Rotation

A new key may name the key it replaces, and both work until the old one
expires or is revoked. A rotation that requires a coordinated cutover will
not happen, and the key will live for three years instead.

`last_used_at` is recorded, and `GET /ingest/keys/stale` (default 30 days)
lists the keys nobody has used: either dead integrations or someone else's.
Nothing alerts on them; an `ingest.manage` holder looks.

### Request handling

- `POST /api/v1/ingest` with `Authorization: Bearer noct_sk_live_…`
- **Idempotency key** per request (`Idempotency-Key`), deduped for 24h.
  Retrying clients are the norm, not the exception.
- Optional HMAC request signing (`X-NocTORnal-Signature` over timestamp and
  raw body) for higher assurance is **not built**.
- Respond `202 Accepted` with a `batch_id` immediately. Parse
  asynchronously. Never block the client on processing. The raw bytes are
  stored first (content-addressed, in the raw bucket `noctornal-raw`, with
  no object lock and a short category clock, because it is somebody else's
  unvetted bytes); nothing is parsed in the request.
- Parsing is a separate step: `POST /ingest/batches/{id}/parse`, by an
  `ingest.manage` holder, so a malformed 50MB dump is a background problem
  rather than a request timeout. It parses into the unattached queue and
  takes no case: a record goes into a case afterwards, with
  `POST /ingest/records/{id}/attach`, on the word of somebody who works that
  case (`ingest.replay` on it). A parse request that names a case is refused
  with a 400 that says so.

---

## Part 2: Parsing and categorisation

```
POST → auth → limits → raw persist → 202
parse: format detect → schema map → categorise → extract selectors
  → score → route → triage queue
       │
       └── unparseable → DEAD LETTER (never dropped)
```

**Persist raw before parsing, always.** When the parser is wrong (and it
will be) you re-parse from the original rather than asking a partner to
resend three months of feed.

### Format detection

Sniff, do not trust `Content-Type`. `detect_format` tells ZIP, GZIP, a JSON
array, a JSON object, NDJSON, CSV and plain text apart, NDJSON being the
right default for volume. STIX 2.1 bundles and MISP events arrive as JSON
and are not given STIX or MISP semantics; syslog, CEF/LEEF and 7z are not
recognised as such.

### Categories

`document.category`, the taxonomy that makes the bucket navigable:

| Category | Notes |
|---|---|
| `STEALER_LOG` | High volume, high value, **high risk**. See below |
| `CREDENTIAL_DUMP` | Combo lists, breach data |
| `DATABASE_LEAK` | Structured dumps, often forum databases |
| `RANSOM_LEAK_POST` | Leak site listings, victim, deadline, sample data |
| `MARKET_LISTING` | Shop and vendor listings |
| `FORUM_POST` | The default from forum collectors |
| `CHAT_EXPORT` | From `docs/10` channels |
| `PASTE` | Pastebin-class |
| `IOC_FEED` | Machine-readable indicators |
| `VENDOR_REPORT` | CTI vendor reporting |
| `MALWARE_SAMPLE` | Routes to `docs/11`, not the normal bucket |
| `BLOCKCHAIN_TX` | Chain analytics output |
| `SANCTIONS_LIST` | OFAC and equivalents |
| `COURT_RECORD` | Indictments, filings |
| `TELEMETRY` | Sensor and honeypot logs |
| `UNKNOWN` | Honest default. Better than a confident wrong label |

Categorisation is structure first, then the key's declaration. A structural
match is trusted over the declaration, because structure is what arrived and
the declaration is what somebody configured once; the key's declared category
is the fallback (at confidence 0.5), and UNKNOWN otherwise. There is no
content classifier. Keep the confidence and let analysts correct it
(`POST /ingest/records/{id}/category`); corrections are training data, though
nothing trains on them yet.

### Triage scoring: the part that makes it usable

Volume is the enemy. Every record is scored for review priority, and the
row lists each term that moved the score:

```
priority = 10 · distinct watched selector found in the record
         +  2 · a high-risk category (STEALER_LOG, CREDENTIAL_DUMP, DATABASE_LEAK)
         −  8 · a near duplicate of an earlier record
         (never below 0)
```

A record containing a selector on someone's watchlist should surface in
seconds. A generic combo list should sink, silently, to the bottom. Active-case
entity match, strong-selector density, source reliability and recency are not
terms of the score.

**Near-duplicate suppression matters more than it sounds.** Feeds
re-publish each other constantly. Without clustering the queue fills with
the same leak post from nine sources and analysts stop reading it. The
fingerprint is a simhash over path-qualified values only (field names do not
count as content, and the envelope keys a mirror adds, such as `source_url`
and `seen_at`, are left out, so a repost is still recognisably the same
post), and fingerprints from different `SIMHASH_VERSION`s are never compared.

### Dead letters

Anything unparseable goes to a dead-letter queue with the raw payload, the
error, and the parser version. Visible in admin, with a repair-and-replay
action (`POST /ingest/dead-letters/{id}/replay`; the original fragment is
not overwritten).

Silent drops are how you discover six months later that a feed has been
half-failing. A key's dead-letter rate over the last 24 hours is shown with
the key (`dead_letter_rate_24h`); nothing alerts on it. A rising rate is
usually the partner changing their schema without telling you.

---

## Stealer logs deserve their own paragraph

They are the highest-volume, highest-value and highest-risk thing you will
ingest, and they are the most likely route by which this platform becomes
a data protection incident rather than an intelligence asset.

A single log archive contains credentials, cookies, session tokens, crypto
wallets, autofill data and documents belonging to **one victim who is not
your subject**. A feed contains thousands.

Handle differently from everything else:

- Own compartment, tighter than the parent case (the key's forced
  compartment)
- Victims as `VICTIM` nodes (`ingest.victim_credential.victim_node_id`). The
  `is_incidental` flag exists on conversation participants (docs/08), not on
  graph nodes.
- **No free-text search across victim PII** without a specific, logged
  authorisation, otherwise the platform is a credential lookup service
  and someone will use it as one. This is impossible rather than forbidden:
  `ingest.victim_credential` has no text index and no plaintext value
  column, and the one lookup, by `value_fingerprint`, takes a live
  two-person `pii_authorisation` or refuses
- Session tokens and live credentials **never rendered in the UI**. Mask
  by default, reveal is a step-up action with an audit event
- Shorter retention than the case default, enforced independently: a
  category clock stamped onto each record at ingest, which can only ever be
  shorter than the case's
- Minimisation review at closure is not built for ingest records

The analytic value is real: infection timelines, victim organisation
attribution, and the C2 and builder metadata that links logs back to the
operator. You can extract almost all of that from the metadata without
ever exposing the credential contents. Design for that.

---

## Part 3: Outbound credentials

Keys NocTORnal uses to pull from third parties: VirusTotal, Shodan,
Censys, urlscan, HIBP, chain analytics, CTI vendors.

A vault of their own, with the shape of the persona vault (`docs/04`):
envelope-encrypted, never returned by the API, rotation tracked.

Additional concerns unique to outbound:

- **Quota tracking per provider.** Burning a monthly VT quota in an hour
  on a bulk enrichment job is a common and avoidable outage.
- **Query attribution leaks.** Looking up a hash or domain on some
  services tells the *provider*, and occasionally the wider world, what
  you are interested in. Some are effectively public. Mark each provider
  with an exposure level and require confirmation for the leaky ones,
  the same treatment as sandbox detonation in `docs/11`.
- Cache aggressively. Enrichment results are stable and quotas are not.

### Outbound lookups (F15)

What exists, and where:

- **The provider registry** (`providers.py`, `http/routers/providers.py`,
  Alembic 0098; Administration, Providers). Nothing is seeded and nothing
  is enabled. Each provider's key sits in `ProviderVault` (docs/05, Lookup
  provider keys), bound to the origin (host and port) and the egress route
  it was entered with: changing either destroys it. Each provider is
  anchored to an inactive `collect.source` of kind VENDOR_API that claims
  cite and nothing polls.
- **Two acts before anything leaves.** An administrator enables a provider;
  the host operator sets `NOCTORNAL_OUTBOUND_LOOKUPS=on` in secrets.env for
  the api and the cron. Either one alone sends nothing.
- **One route per provider** (docs/00 decision 68): `lookup-<key>`, an integration
  route an administrator creates in Administration, Egress. A provider
  whose route is missing or does not admit its host is refused at enable
  and at every send.
- **The exposure ladder.** NONE (your own instance), VENDOR (the vendor
  learns what was asked, under your account) or PUBLIC (anyone watching
  the provider can see it), determined by an administrator with a written
  basis. Every determination below PUBLIC, and every lowering, is a second
  administrator's act, held by the database: an approval names the origin
  (and, for NONE, the private network) it was asked about, and moving a
  provider below PUBLIC to another host, port or private network makes it
  wait for a second administrator again. The ceiling follows the level:
  only NONE may take AMBER, VENDOR takes GREEN at most, PUBLIC CLEAR.
  NONE needs a route entry naming a private network with no public entry
  admitting the same host, which proves the first hop only; the
  provider's own private network rides on its declared rule, so on a host
  with no administrator route it is the whole allowlist.
- **Sign-off in the product** (docs/00 decision 75, read strictly). A lookup to a
  VENDOR or PUBLIC provider names a colleague who holds `lookup.authorise`
  on the case, with a note; nothing is sent until that person signs it off
  in Records, Lookups, within 24 hours. There are no standing
  authorisations. A NONE lookup is sent at once.
- **The lookup ledger** (`lookups.py`, `lookup_adapters.py`,
  `http/routers/lookups.py`, Alembic 0099 to 0101). One row per request,
  one append-only attempt row per send (the quota counts these, in exact
  calendar windows, with a reserve kept for interactive work), and the
  answer kept byte for byte as case material, never labelled below the
  question. Answers become proposals in Triage citing the stored answer,
  never graph. A fresh answer at or above the subject's label is served
  from the per-case cache and nothing is sent.
- **Refused outright:** personal data (by type, by the shape of any span
  in the value, and social profile URLs) toward every provider, because a
  transfer authority is needed and nothing in this build records one (docs/16
  L2); and any hash a sample holds unless prohibited-content screening has
  cleared that sample (docs/11, docs/16 L1), whatever subject kind carries it.
- **Batches** go to NONE providers only, previewed with nothing sent,
  committed against the digest of the preview, and sent by
  `scripts/lookup_drain.py` in the cron loop, which re-checks every rule
  at send time and runs its housekeeping whatever the switch says.
- **Adapters** for VirusTotal v3, Shodan host and MISP restSearch, report
  lookups only: no scan, submission or upload operation exists (docs/16
  L5).

## Schema

`ingest.api_key`, `ingest.batch`, `ingest.record`, `ingest.dead_letter`,
`ingest.category_rule`, `ingest.victim_credential` and
`ingest.pii_authorisation`; see `db/schema.sql`.

## Open questions

1. Who holds inbound keys, internal scripts only, or external partners?
   External changes the support burden and the abuse model substantially.
   The build assumes keys may be held by external partners: write-only
   scope is enforced by a CHECK constraint, IP allowlists and mandatory
   expiry exist. If keys are internal-only, the abuse model is smaller and
   some of that can relax. If external, a support and revocation process is
   needed that the software does not provide (docs/16 D6).
2. Expected volume per day? Under ~10k records/day, Postgres and Redis are
   fine. Above ~1M, the bucket needs a different storage tier. Not decided.
3. Stealer logs in scope? Yes, by operator directive (docs/00 decision 52).
   The compartment is resolved in the schema; the minimisation policy is a
   legal determination that is NOT resolved (docs/16 L2, BLOCKING).
4. Any partner already sending you a feed whose schema you must match? A
   real payload sample is worth more than any amount of speculative
   parser design.
