> # ⚠ ARCHIVED — a snapshot of 2026-07-24, retained for history only
>
> **Everything below was true on 24 July 2026 and most of it is now
> false.** It is kept because it records what the project looked like
> before any of it had run, which is occasionally useful; it is NOT a
> guide to installing or using NocTORnal.
>
> Most conspicuously, this document says *"Nothing has been executed. The
> schema has never touched a real Postgres."* The schema is at **Alembic
> revision 0052** with **1252 passing tests** against a live database.
>
> The root `README.md` used to mark this file **"Read first"**, which meant
> an evaluator following the README met a project that appeared not to know
> its own state within five minutes of arriving (release finding **R18**).
>
> **Go instead to [`../release/INSTALL.md`](../release/INSTALL.md) to
> install, or [`../release/MANUAL.md`](../release/MANUAL.md) to use it.**

---

# Getting started

Practical handoff. Read this at your desk before starting.

---

## What you have

20 files, ~4,500 lines. Two layers:

**Decided** — `docs/00`–`09`, `db/schema.sql`, `db/seed_ontology.sql`.
The domain model, architecture and security posture. Build against these.

**Concept** — `docs/10`–`13`, `db/schema_concept.sql`. Sketches for comms
channels, malware handling and the ingest API. Each ends with open
questions. Do not implement from these until you have answered them.

Nothing has been executed. **The schema has never touched a real
Postgres.** It is structurally checked — balanced, 42 tables, sane
references — but expect it to fail on first load. Fixing that is session
one.

---

## Answer these four first

Each one changes what you build in the first fortnight. Twenty minutes of
thought now saves a rewrite later.

**1. Will this data ever support a prosecution?**
If yes, the WORM evidence store, custody ledger and hash verification stay
in Phase 1 and are load-bearing. If it is purely internal intelligence that
will never be evidence, you can defer all of it and save about a week.

**2. Telegram in the MVP?**
It is the highest-effort, highest-risk adapter — persona management,
FLOOD_WAIT handling, session security, and joining a channel is an overt
act the admin can see. RSS plus XenForo proves the entire pipeline in half
the time. Strong recommendation: defer it.

**3. Stealer logs in scope?**
If yes, the compartment model, PII masking and minimisation policy come
*before* any ingest code. This is the most likely route by which the
platform becomes a data protection incident rather than an intelligence
asset.

**4. Biggest realistic case — hundreds of nodes, or hundreds of thousands?**
Under ~10k the default rendering and analytics strategies are fine. Above
that, server-side layout and level-of-detail rendering stop being optional
and the Phase 2 plan changes.

The remaining six questions in `docs/00-decisions.md` can wait until
Phase 3.

---

## Day one

```bash
cd infra && docker compose up -d
```

Postgres boots with extensions only (`db/init/`). The schema and seed come
from Alembic — one owner, no drift. From the repo root:

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r db/requirements.txt
export DATABASE_URL="postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal"
alembic upgrade head
```

(PowerShell: `$env:DATABASE_URL = "postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal"`.)
`db/schema.sql` and `db/seed_ontology.sql` remain as readable reference —
any schema change lands as a new migration AND is mirrored there.

Verify:

```bash
docker compose exec postgres psql -U noctornal -d noctornal \
  -c "\dt core.*" -c "select count(*) from core.edge_type;"
```

Twelve-ish core tables and ~45 edge types means it loaded.

MinIO console at `:9001`, Mailpit at `:8025`, OpenFGA playground at
`:3001` (host 3000 is reserved for the Next.js dev server).

---

## First four work sessions

Work one at a time. Do not batch them.

### Session 1 — make the schema real

> Read `CONVENTIONS.md` and `db/schema.sql`. Load the schema against the
> Postgres in `infra/docker-compose.yml` and fix every error until it
> applies cleanly from an empty database. Then load `db/seed_ontology.sql`.
>
> Do not simplify the model to make errors go away — if something needs
> restructuring, tell me first. I especially expect problems around the
> deferred foreign keys, the enum comparison in `enforce_tlp_floor`, and
> the `vector(768)` columns if pgvector's HNSW indexes need different
> syntax.
>
> When it applies cleanly, split it into Alembic migrations: one concern
> per migration, all reversible. Show me the migration list before you
> write them.

### Session 2 — the ontology package

> Read `docs/01-domain-model.md` and `db/seed_ontology.sql`. Build
> `packages/ontology` as the single source of truth for node types, edge
> types and selector types, generating both Python and TypeScript types
> plus the SQL seed from one definition file.
>
> Include the per-selector normalisers referenced in the `normaliser`
> column. `tox_pubkey` truncates a 76-hex Tox ID to the first 64 — see
> invariant 9 in `CONVENTIONS.md`. Write tests for every normaliser, and
> specifically test that a rotated nospam produces the same normalised
> value.

### Session 3 — authentication

> Read `docs/05-security-rbac.md`. Implement password plus TOTP auth in
> `apps/api`: Argon2id, RFC 6238 TOTP with ±1 window drift, and TOTP
> replay protection by storing the last accepted counter.
>
> Sessions are server-side and opaque, token hashed not stored, absolute
> 12h and idle 30min expiry both enforced server-side.
>
> Write the failing tests first, including one named for the replay
> protection.

### Session 4 — the authorisation gate

> Read `docs/05-security-rbac.md`. Implement the five-part access check as
> a single function that every endpoint calls: role grants the verb, case
> assignment grants the row, TLP clearance dominates, compartments are a
> subset, and step-up freshness is checked when the permission requires it.
>
> Write the tests first. There must be a test that fails if any one of the
> five checks is removed.

Then follow Phase 0 → 1 in `docs/09-roadmap.md`.

---

## The one thing that matters most

**Build the assertion layer in Phase 1.**

It is the expensive decision and the only one that cannot be retrofitted.
Every alternative — writing edges directly and "adding sources later" —
ends with a graph of unsourced claims that nobody can audit, retract or
defend. If you skip it in Phase 1 it is never getting built.

Concretely: there is no code path that writes to `node` or `edge` without
creating an `assertion` in the same transaction. Test it, name the test
after invariant 1, and let it fail the build.

---

## Stop after Phase 1 and use it

Once an analyst can build a case entirely by hand and every edge answers
"why do we believe this?" in one click — **stop and run a real case
through it for a week.**

Everything downstream assumes the model is right. A week of real use will
find the places it is not, and changing the model in week 3 costs hours
where changing it in week 10 costs weeks.

---

## What not to do first

- **Don't start with the sociogram.** It is the fun part and it will look
  impressive over a model that cannot support it. Phase 2, not Phase 1.
- **Don't turn on collection early.** A firehose into a half-built model
  produces a landfill you then clean by hand.
- **Don't build a sandbox.** Integrate with CAPEv2 or a vendor.
- **Don't add Neo4j as the system of record.** The projection pattern in
  `docs/02` gives you graph analytics without splitting your source of
  truth.
- **Don't let auto-extraction write to the graph.** Proposals only.

---

## Working on this

- **Reference invariants by number.** "This must not violate invariant 3
  in CONVENTIONS.md" keeps the non-negotiables in context and gives tests names
  that still explain themselves in six months.
- **Ask for the failing test first.** Especially for the invariants.
- **Review migrations before they apply.** Always.
- **One roadmap item per session** where the item is substantial.
- **When it proposes simplifying the assertion model, say no.** It will,
  because the model is genuinely more complex than a normal CRUD app, and
  the complexity is the point.

---

## Rename it — DONE

Named **NocTORnal** on 2026-07-24 (scaffold codename was `lattice`). The
identifier form `noctornal` is used for the database, the compose project,
the MinIO buckets and the key prefix (`noct_sk_…`); `NocTORnal` in prose.
The only surviving "lattice" is the mathematical term in
`docs/05-security-rbac.md` (TLP dominance ordering), which is not the name.
