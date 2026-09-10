# CONVENTIONS.md — working agreement for this repo

Read this before writing code. Read `docs/00-decisions.md` before proposing
architecture changes.

## What this is

NocTORnal is a HUMINT / social network analysis platform for cybercrime
investigation. Analysts build a graph of criminal actors, groups, personas
and the trust relationships between them, backed by evidence with a chain
of custody, fed by monitored forums and channels.

Comparable products: SL Crimewall, Maltego, i2 Analyst's Notebook, UCINET
(for the SNA maths), Obsidian (for the linked-notes feel).

## Non-negotiable invariants

Violating any of these is a bug even if tests pass.

1. **Nothing is a fact.** Every node attribute and every edge traces to at
   least one row in `assertion`, with a source, an Admiralty grading and a
   time. There is no code path that writes a graph element without one.

2. **A handle is not a person.** `IDENTITY` (persona) and `PERSON`
   (assessed human) are different node types. They join via
   `ATTRIBUTED_TO`, which carries a confidence and is reversible. Never
   add a "real_name" column to `IDENTITY`.

3. **Machines propose, analysts dispose.** Extractors and inference jobs
   write to `proposal`. They never write to `node` or `edge` directly.
   There is no direct-write exception: a strong (`is_strong`) selector
   already attributed to another node raises `StrongSelectorConflict` as
   a merge *lead*, and the merge is made by an analyst (`merges.py`),
   reversibly and with an audit event. (The 2026-07 text allowed an
   automatic merge on a strong match; it was never built and is
   superseded as of 2026-09-09.)

4. **Inferred edges stay visually and structurally distinct.** `is_inferred
   = true` renders dashed and is excluded from metrics unless the
   projection explicitly opts in. An inferred edge never silently becomes
   an asserted one.

5. **History is superseded, never overwritten.** No destructive `UPDATE` on
   `assertion`: a claim's own columns are never written again. The one
   exception, decided 2026-09-09: a retraction is a *marked row*, not a
   supersession. `retract_assertion` stamps `retracted_at`,
   `retracted_by` and `retraction_reason` once, from NULL (`WHERE
   retracted_at IS NULL`; zero rows is an error), and the projection
   drops the row. There is nothing to supersede it with — a retraction
   withdraws a claim rather than replacing one. A correction is a new
   assertion. `superseded_at`/`superseded_by` exist (0007) and the read
   side honours them, but no code path writes them yet.

6. **The audit log is append-only.** No code, migration or admin tool
   gains `UPDATE` or `DELETE` on `audit.event`.

7. **Credentials never leave the vault.** `collection_account.secret_*`
   is envelope-encrypted at rest (AES-256-GCM under `NOCTORNAL_TOTP_KEK`,
   the same scheme as TOTP secrets) and decrypted only inside
   `PersonaVault.use()`, a context manager that yields the plaintext to
   one block, drops it and audits the use. There is no `get_secret()`,
   nothing serialises a plaintext into a response, and every adapter error
   is `redact()`-ed before it is stored. **The vault runs inside the API
   process** — there is no separate collector — so this is a guarantee
   about the SHAPE of the code, not about a network boundary: a
   compromised API host is a compromised vault. (Reworded 2026-09-09.
   Until then this read "never leave the collector, never in the API
   process", which the topology has never backed. Splitting collection
   into its own process is a deliberate not-yet — `docs/02`.)

8. **TLP gates egress.** Every outbound path — SMTP, Jira, webhook,
   export — checks classification first. `AMBER_STRICT` and `RED` never
   leave the boundary. Write the check once, in one place, and call it
   from every integration.

9. **Durable identifiers, not displayed ones.** Tox indexes on the 64-hex
   public key, never the 76-hex ID (nospam is rotatable). Telegram
   indexes on the numeric ID, never `@username` (recycled). See
   `comms.platform.durable_selector_type` — it exists for this reason.

10. **Samples never render, never execute.** The binary is only ever an
    encrypted archive download from a *separate origin*. Sample metadata
    may render; sample bytes may not. No sandbox attribute combines
    `allow-scripts` with `allow-same-origin`.

11. **Ingest keys are write-only.** A `case:read` scope on an
    `ingest.api_key` is a bug, and there is a check constraint saying so.
    A leaked ingest key means junk data, never the case file.

12. **Nothing is silently dropped.** Unparseable input goes to
    `ingest.dead_letter` with the raw fragment. Silent drops are how you
    find out six months later that a feed has been half-failing.

## Concept vs decided

`docs/00`–`09` are decided, and `db/schema.sql` is a generated mirror of
the decided schema (the migrations are authoritative; `db/README.md`).
`docs/10`–`12` and `db/concept/schema_concept.sql` are sketches — read the
open questions at the end of each before implementing, and expect to
change the schema.

## Build order

Follow `docs/09-roadmap.md`. Do not start the collection layer before the
graph and assertion layer are working end to end — a firehose into a
half-built model produces a landfill.

## Stack

See `docs/02-architecture.md` for the reasoning. What is in the tree, as
of 2026-09-09:

- Postgres 16 + pgvector as the system of record; 59 Alembic revisions
  (`0001`–`0059`), `db/schema.sql` regenerated from them
- Python 3.12+ / FastAPI — **one process**, serving the REST API under
  `/api/v1`, the analyst console under `/ui`, the `/api/v1/live`
  WebSocket, and running the collectors, the analytics and the
  notification drain itself. There is no worker process and no queue
  (decision 30; `dispatch_due()` and `run_once` are called, not scheduled)
- `igraph` (C core) + `leidenalg` for SNA maths — not NetworkX, which will
  not hold up
- A vanilla HTML/CSS/JS console: no framework, no build step, no bundler,
  served same-origin under a strict CSP (`script-src 'self'`, no inline
  script)
- A Canvas 2D sociogram with a hand-written ForceAtlas2 + Barnes-Hut
  layout in a Web Worker (decision 37)
- Redis for the rate-limit meter (GCRA in one Lua script) and cache
- MinIO (S3 + object lock) for evidence, raw captures and samples
- Mailpit as the development SMTP sink
- Authorisation is the five-part gate in `security/access.py`, answered
  from `iam.*` in Postgres — no external authorisation engine
- The 2026-07 sketch's Next.js, sigma.js/WebGL, OpenFGA/SpiceDB, NATS and Arq/Celery are not in the tree; they were superseded (decisions 8, 9, 30, 37; compose R13 removed OpenFGA and NATS on 2026-07-26)

## Conventions

- Migrations: Alembic, one concern per migration, reversible on an EMPTY
  database — which is the contract CI proves, by round-tripping
  `head → base → head` before the suite runs.
  **Reversible does not mean reversible on a database with data in it, and
  it is not meant to.** Downgrading past `0017` unwinds the ontology and
  role seed, and five foreign keys into those seeded rows have no
  `ON DELETE CASCADE` — `iam.case_assignment.role_key` and
  `iam.user_role.role_key` among them, with a second instance in `0031`.
  So the downgrade stops with a foreign-key violation on any deployment
  that has ever assigned a case or a role. That refusal is the DESIGNED
  behaviour: cascading it would silently delete graph and authorization
  data to make a rollback succeed, which is data destruction wearing a
  rollback's name, and it would drive straight through the soft-delete-only
  invariant. If you need to go back past 0017 on a live database, restore a
  backup — do not make the downgrade "work".
- IDs: v4 UUIDs — `uuid4()` app-side, `gen_random_uuid()` as the column
  default in the database. Nothing sorts on an id. (The 2026-07 convention was UUIDv7 app-side; it was never adopted and is superseded as of 2026-09-09 — `pg_uuidv7` is not installed.)
- Times: `timestamptz`, UTC in the database, rendered in the user's zone.
- Money and weights: `numeric`, never float.
- API: REST under `/api/v1`, `limit`-capped pagination (`limit: int =
  Query(200, le=1000)` in `http/routers/read.py`; no cursors),
  `problem+json` errors (RFC 9457). (Cursor pagination was the 2026-07
  convention; it was never implemented and is superseded as of
  2026-09-09.)
- Tests: every invariant above has a test named after it.
- Secrets: environment or Vault. Never a default value in code.

## When you are unsure

Ask before: changing the assertion model, adding a node or edge type that
duplicates an existing one, weakening an access check, or adding a
dependency that touches evidence handling. Everything else, use judgement
and leave a note in `docs/00-decisions.md`.
