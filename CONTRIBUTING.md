# Contributing

Read [`CLAUDE.md`](CLAUDE.md) first — it is the working agreement, and it
is short. Read [`docs/00-decisions.md`](docs/00-decisions.md) before
proposing an architecture change.

## The one rule that is different here

**A violation of one of the [twelve
invariants](README.md#the-twelve-invariants) is a bug even if every test
passes.** They are listed in `CLAUDE.md` and each has a test named after
it. If your change makes one of them conditionally true, the change is
wrong even when CI is green — eight adversarial reviews have each found a
real defect under a fully passing suite, and three of those defects were
green tests asserting the bug.

## Setting up

```bash
# Windows
powershell -ExecutionPolicy Bypass -File .\release\install.ps1
# macOS / Linux
chmod +x release/install.sh && ./release/install.sh
```

Then, for the full suite:

```bash
DATABASE_URL="postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal" \
  .venv/bin/python -m pytest apps/api/tests packages/ontology -q
```

**1252 passed, 12 skipped.** Without `DATABASE_URL` you get ~700 skips,
which is a correct result — half the suite is deliberately database-free.

```bash
.venv/bin/python -m ruff check apps packages scripts
```

## House style

- **Comments explain *why*, and especially why-not.** The codebase is
  unusually heavily commented and that is deliberate: most of the comments
  record a decision that has a plausible-looking alternative, or a bug that
  was found the hard way. If you remove one, you are removing the reason
  somebody will otherwise re-introduce the defect.
- **Match the surrounding code.** Comment density, naming, idiom.
- **British spelling** in prose and identifiers (`normalise`,
  `classification`, `authorisation`).
- Times are `timestamptz`, UTC in the database. Money and weights are
  `numeric`, never float. IDs are UUIDv7 generated app-side.

## Changing the ontology

`packages/ontology/src/noctornal_ontology/definition.py` is the **only**
editable source of node, edge and selector types.

```bash
PYTHONPATH=packages/ontology/src .venv/bin/python -m noctornal_ontology.generate
```

Then ship the change as a **new Alembic migration**. Never by editing
revision 0017, and never by re-running the generated seed — it is
`ON CONFLICT DO NOTHING`, so re-applying it over a changed row silently
keeps the old one.

Adding a node or edge type that duplicates an existing one needs
discussion first. So does anything that changes the assertion model,
weakens an access check, or adds a dependency touching evidence handling.

## Migrations

One concern per migration. Always reversible — and **test the downgrade**,
because ordering bugs hide there. A recent example: a `DROP SCHEMA …
RESTRICT` placed in the wrong revision of a four-migration set would have
failed on unwind, and only running `alembic downgrade` found it.

```bash
.venv/bin/python -m alembic downgrade <previous>
.venv/bin/python -m alembic upgrade head
```

The migration docstring should explain what defect it closes and what it
*cannot* fix. Several existing ones say plainly that they repair a format
but cannot undo damage already done; that honesty is the house style.

## Tests

Every invariant has a test named after it, and new safety-relevant
behaviour should get one whose name is the claim it defends. Prefer:

```python
def test_a_presented_caller_id_never_becomes_a_selector():
```

over `test_selector_candidates_2`. The test name is documentation that
cannot go stale silently.

Where a rule is enforced in both application code and the schema, **test
both** — the service refusal gives the caller a sentence, the constraint
is what holds when a migration or a `psql` session does the write.

## The UI

Plain HTML, CSS and ES modules. No build step, no framework, no
`node_modules`, and that is not going to change — see the README's
reasoning.

Every value that reaches the DOM goes through `textContent`, never markup.
`apps/api/tests/test_ui_invariants.py` enforces it by reading `app.js`, and
also constrains `.src` assignments to same-origin API paths. If you need
an exception, the answer is almost certainly no.

## Reporting security issues

Not through a public issue. See [`SECURITY.md`](SECURITY.md).

## Licence

Contributions are accepted under the **AGPL-3.0-or-later** licence of the
project. See [`NOTICE.md`](NOTICE.md) for why it is that licence and why a
permissive one was never available.
