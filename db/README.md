# db/

- **`migrations/`** — the Alembic chain, the ONE authoritative schema
  (docs/00 decision 17). `alembic upgrade head`; one concern per revision,
  every revision reversible on an empty database (CI round-trips
  head → base → head). The reasoning for each table's shape lives in the
  docstring of the revision that created it.
- **`schema.sql`** — a GENERATED mirror of the schema at head, written by
  `scripts/dump_schema.py` (`pg_dump --schema-only --no-owner
  --no-privileges`, with session settings, version comments and pg_dump's
  per-run `\restrict` tokens removed). Its header names the revision it
  mirrors. CI regenerates it and fails on any difference ("Schema mirror
  matches the migrations"), and `apps/api/tests/test_schema_mirror.py`
  holds the header to the chain's head and the migrations' schemas to the
  file. **Do not edit it by hand.** Until 2026-09-09 it was hand-maintained
  and named five of the ten schemas.
- **`seed_ontology.sql`** — REFERENCE ONLY since 2026-07-24. The vocabulary
  that actually loads is revision 0017 plus every later revision that
  extends it; `packages/ontology/generated/seed_ontology.sql` is the
  generated form of the current definition.
- **`init/00-extensions.sql`** — the only thing initdb runs. `CREATE
  EXTENSION` needs superuser, which the migration role must never be.
- **`concept/`** — sketches for docs/10–12. Not migrated, not mirrored,
  deliberately less settled than anything above.
- **`requirements.txt`** — what CI installs before `alembic upgrade head`.
