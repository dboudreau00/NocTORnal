# 12. Ingest API keys and feed categorisation

**Status: BUILT** (Phase 9, migrations 0033 onward). This document is the
domain reasoning; `ARCHITECTURE.md` describes what was built.

Two distinct things share the word "key" and should not share an
implementation:

- **Inbound keys** (`sk_`), machines push data *into* NocTORnal
- **Outbound credentials**, NocTORnal pulls *from* third-party APIs

Different threat models. Inbound keys are held by parties you do not
control and will leak. Outbound credentials are yours to protect and sit
in the vault described in `docs/04`.

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
- you can register the pattern with GitHub secret scanning
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

Argon2 is correct for user passwords. HMAC with a pepper in an HSM or
Vault is correct for machine keys. The difference is that machine keys are
high-entropy by construction, so the slow-hash defence against guessing is
unnecessary.

### Key properties

Every key carries:

| Property | Why |
|---|---|
| **Scopes** | `ingest:write` only. **An ingest key must never be able to read.** A leaked write-only key means junk data; a leaked read key means the case file |
| **Bound source** | One key ↔ one logical feed, so provenance is unambiguous |
| **Declared schema** | The payload shape this key sends. Anything else is rejected at the boundary |
| **Default grading** | Admiralty reliability applied to everything from this feed |
| **Classification ceiling** | Nothing from this key may be marked above X |
| **IP allowlist** | CIDRs. Cheap and effective |
| **Rate + size limits** | Per key, enforced in Redis |
| **Expiry** | Mandatory. Default 90 days, no "never" option |
| **Owner** | A named human, not a team. Orphaned keys are how ingest paths outlive their purpose |

### Rotation

Two keys active per source during an overlap window. Issue the new key,
both work, the old one goes read-only-warning, then dies on schedule. A
rotation that requires a coordinated cutover will not happen, and the key
will live for three years instead.

Surface `last_used_at` and alert on keys unused for 30 days. Those are
either dead integrations or someone else's.

### Request handling

- `Authorization: Bearer noct_sk_live_…`
- Optional **HMAC request signing** for higher assurance:
  `X-NocTORnal-Signature: t=<ts>,v1=<hex>` over timestamp + raw body, with a
  five-minute replay window. Offer it; require it for high-volume or
  high-trust feeds.
- **Idempotency key** per request, deduped for 24h. Retrying clients are
  the norm, not the exception.
- Accept `application/json`, `application/x-ndjson`, `text/csv`,
  `application/gzip`. NDJSON is the right default for volume.
- Respond `202 Accepted` with a `batch_id` immediately. Parse
  asynchronously. Never block the client on processing.

---

## Part 2: Parsing and categorisation

```
POST → auth → limits → raw persist → format detect → schema map
  → categorise → extract selectors → score → route → triage queue
       │
       └── unparseable → DEAD LETTER (never dropped)
```

**Persist raw before parsing, always.** When the parser is wrong (and it
will be) you re-parse from the original rather than asking a partner to
resend three months of feed.

### Format detection

Sniff, do not trust `Content-Type`. In rough order of what actually
arrives: NDJSON, JSON array, CSV/TSV, STIX 2.1 bundle, MISP event,
syslog, CEF/LEEF, plain text, ZIP or 7z of any of the above.

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

Categorisation is: declared by the key → refined by structure → refined by
content classifier. Keep the confidence and let analysts correct it;
corrections are training data.

### Triage scoring: the part that makes it usable

Volume is the enemy. Score every record for review priority:

```
priority =  w1 · watched_selector_hit        ← dominant term
          + w2 · active_case_entity_match
          + w3 · strong_selector_density
          + w4 · source_reliability
          + w5 · recency
          − w6 · near_duplicate_penalty
```

A record containing a selector on someone's watchlist should surface in
seconds. A generic combo list should sink, silently, to the bottom.

**Near-duplicate suppression matters more than it sounds.** Feeds
re-publish each other constantly. Without minhash or simhash clustering,
the queue fills with the same leak post from nine sources and analysts
stop reading it.

### Dead letters

Anything unparseable goes to a dead-letter queue with the raw payload, the
error, and the parser version. Visible in admin, with a repair-and-replay
action.

Silent drops are how you discover six months later that a feed has been
half-failing. Alert when a key's dead-letter rate crosses a threshold.
That is usually the partner changing their schema without telling you.

---

## Stealer logs deserve their own paragraph

They are the highest-volume, highest-value and highest-risk thing you will
ingest, and they are the most likely route by which this platform becomes
a data protection incident rather than an intelligence asset.

A single log archive contains credentials, cookies, session tokens, crypto
wallets, autofill data and documents belonging to **one victim who is not
your subject**. A feed contains thousands.

Handle differently from everything else:

- Own compartment, tighter than the parent case
- Victims as `VICTIM` nodes flagged `is_incidental`
- **No free-text search across victim PII** without a specific, logged
  authorisation, otherwise the platform is a credential lookup service
  and someone will use it as one
- Session tokens and live credentials **never rendered in the UI**. Mask
  by default, reveal is a step-up action with an audit event
- Shorter retention than the case default, enforced independently
- Minimisation review at closure

The analytic value is real: infection timelines, victim organisation
attribution, and the C2 and builder metadata that links logs back to the
operator. You can extract almost all of that from the metadata without
ever exposing the credential contents. Design for that.

---

## Part 3: Outbound credentials

Keys NocTORnal uses to pull from third parties: VirusTotal, Shodan,
Censys, urlscan, HIBP, chain analytics, CTI vendors, Telegram bot tokens.

Same vault as personas (`docs/04`): envelope-encrypted, decrypted only in
the worker, never returned by the API, rotation tracked.

Additional concerns unique to outbound:

- **Quota tracking per provider.** Burning a monthly VT quota in an hour
  on a bulk enrichment job is a common and avoidable outage.
- **Query attribution leaks.** Looking up a hash or domain on some
  services tells the *provider*, and occasionally the wider world, what
  you are interested in. Some are effectively public. Mark each provider
  with an exposure level and require confirmation for the leaky ones,
  the same treatment as sandbox detonation in `docs/11`.
- Cache aggressively. Enrichment results are stable and quotas are not.

### Status: BUILT (outbound lookups, roadmap F15, 2026-09-24)

What exists, and where:

- **The provider registry** (`providers.py`, `http/routers/providers.py`,
  Alembic 0098; Administration, Providers). Nothing is seeded and nothing
  is enabled. Each provider's key is envelope-sealed in the same vault
  shape as personas (`ProviderVault`: store, clear and use, and nothing
  that returns a key), audited before it is opened, and bound to the
  origin (host and port) and the egress route it was entered with:
  changing either destroys it. Each provider is anchored to an inactive
  `collect.source` of kind VENDOR_API that claims cite and nothing polls.
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
  in the value, and social profile URLs) until a transfer authority is
  recorded, and any hash a sample holds until prohibited-content screening
  exists, whatever subject kind carries it.
- **Batches** go to NONE providers only, previewed with nothing sent,
  committed against the digest of the preview, and sent by
  `scripts/lookup_drain.py` in the cron loop, which re-checks every rule
  at send time and runs its housekeeping whatever the switch says.
- **Adapters** for VirusTotal v3, Shodan host and MISP restSearch, report
  lookups only: no scan, submission or upload operation exists (docs/16
  L5). None has been verified against its live service, and the product
  says so.

## Draft schema

`ingest.api_key`, `ingest.batch`, `ingest.record`, `ingest.dead_letter`,
`ingest.category_rule`, shipped; see `db/schema.sql`.

## Open questions

1. Who holds inbound keys, internal scripts only, or external partners?
   External changes the support burden and the abuse model substantially.
2. Expected volume per day? Under ~10k records/day, Postgres and Redis are
   fine. Above ~1M, the bucket needs a different storage tier.
3. Stealer logs in scope for the MVP? If yes, resolve the compartment and
   minimisation policy before writing any ingest code.
4. Any partner already sending you a feed whose schema you must match? A
   real payload sample is worth more than any amount of speculative
   parser design.
