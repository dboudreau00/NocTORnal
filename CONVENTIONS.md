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
   The only exception is auto-merge on a `is_strong` selector match, and
   even that creates a reversible merge with an audit event.

4. **Inferred edges stay visually and structurally distinct.** `is_inferred
   = true` renders dashed and is excluded from metrics unless the
   projection explicitly opts in. An inferred edge never silently becomes
   an asserted one.

5. **History is superseded, never overwritten.** No destructive `UPDATE` on
   `assertion`. Set `superseded_at`/`superseded_by` and insert.

6. **The audit log is append-only.** No code, migration or admin tool
   gains `UPDATE` or `DELETE` on `audit.event`.

7. **Credentials never leave the collector.** `collection_account.secret_*`
   is decrypted only inside the collection worker, never in the API
   process, never serialised to a response, never logged.

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

`docs/00`–`09` and `db/schema.sql` are decided. `docs/10`–`12` and
`db/schema_concept.sql` are sketches — read the open questions at the end
of each before implementing, and expect to change the schema.

## Build order

Follow `docs/09-roadmap.md`. Do not start the collection layer before the
graph and assertion layer are working end to end — a firehose into a
half-built model produces a landfill.

## Stack

See `docs/02-architecture.md` for the reasoning. Summary:

- Postgres 16 + pgvector as the system of record
- Python 3.12 / FastAPI for the API
- Python workers (Arq or Celery) for collection and analytics
- `igraph` (C core) for SNA maths — not NetworkX, which will not hold up
- Next.js 15 / TypeScript / Tailwind for the front end
- `graphology` + `sigma.js` (WebGL) for the sociogram
- Redis for cache, queue and rate limiting
- MinIO (S3 + object lock) for evidence and raw captures
- OpenFGA or SpiceDB for relationship-based authorisation

## Conventions

- Migrations: Alembic, one concern per migration, always reversible.
- IDs: UUIDv7 generated app-side so they sort by creation time.
- Times: `timestamptz`, UTC in the database, rendered in the user's zone.
- Money and weights: `numeric`, never float.
- API: REST under `/api/v1`, cursor pagination, `problem+json` errors.
- Tests: every invariant above has a test named after it.
- Secrets: environment or Vault. Never a default value in code.

## When you are unsure

Ask before: changing the assertion model, adding a node or edge type that
duplicates an existing one, weakening an access check, or adding a
dependency that touches evidence handling. Everything else, use judgement
and leave a note in `docs/00-decisions.md`.
