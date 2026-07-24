# noctornal-ontology

The single source of truth for the NocTORnal graph vocabulary: node
types, edge types, selector types, and the per-selector normalisers.

```
src/noctornal_ontology/definition.py    THE definition (edit this)
src/noctornal_ontology/normalisers.py   canonical matching forms (edit this)
src/noctornal_ontology/generate.py      emits generated/ (never edit outputs)
generated/ontology.ts                   TypeScript types for apps/web
generated/seed_ontology.sql             SQL seed (ontology tables only)
```

## Rules

- **Change the definition → regenerate → ship a new data migration.**
  `python -m noctornal_ontology.generate` rewrites `generated/`;
  `--check` exits 1 on drift (use in CI). Alembic revision 0017 seeded
  the initial vocabulary; later vocabulary changes are NEW revisions —
  never edits to 0017.
- **Normalisers are total, best-effort `str -> str`.** They never raise;
  weird input comes back best-effort. Validation is a separate concern
  (`selector_type.validator_regex`). `norm(norm(x)) == norm(x)` is a
  tested invariant.
- **Strength is conservative** (invariant: a false merge silently invents
  relationships between two real people). Rotatable or recycled
  identifiers — Telegram @usernames, the 76-hex Tox ID, handles — are
  never `is_strong`.

## Known normaliser limits (deliberate, revisit when the app layer lands)

- `e164`: cannot complete a bare national number to E.164 without a
  country hint; full inference belongs to libphonenumber in the app.
- `eip55`: canonical matching form is `0x` + lowercase hex. EIP-55
  checksum *validation* needs keccak256 and belongs to the validator/UI
  layer.
- `punycode_lower`: stdlib IDNA (2003); UTS-46 edge cases (emoji
  domains) fall back to lowercase Unicode.

## Tests

```bash
python -m pytest packages/ontology/tests -q
```

Unit tests always run. `test_db_parity.py` is integration-gated on
`DATABASE_URL` and asserts the definition equals the live seed
row-for-row. The rotated-nospam test
(`TestToxPubkey::test_rotated_nospam_same_norm_value`) is the invariant-9
regression test — the 76-hex Tox ID truncates to its 64-hex public key so
a rotated nospam still collides with the same actor.
