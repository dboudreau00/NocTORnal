# Vendored MaaSSpec data

The tests in this directory's neighbours (`test_maasspec_mapper.py`, `test_maasspec_parity.py`, `test_maasspec_ingest_pg.py`,
`test_maasspec_switch_api.py`) read these files. They are copies, never edited by hand.

- `maasspec_spectrum.schema.json` is MaaSSpec's generated JSON Schema (`schema/spectrum.schema.json`). The schema is the same
  in MaaSSpec 0.1.0 and in the 0.3.1 tree, because the document shape did not change between them.
- `maasspec_fixture.spectrum.json` is `examples/fixture.spectrum.json` from MaaSSpec.
- `maasspec_spectra.json` holds spectra made by MaaSSpec's own importers and analysers from synthetic input (the feed
  fixtures of its tests, a hand-made CAPE report, an archive and a sample). It was made with MaaSSpec at commit 27256a8, before
  the later fixes to scoring and timestamps; those change values, not the shape, and `test_maasspec_parity.py` iterates
  whatever the file holds.

When MaaSSpec's contract changes (a model, so its `maasspec_version` constant), replace the schema and the spectra from the new
tree: the drift tests in `test_maasspec_parity.py` fail until `noctornal_api/maasspec.py` agrees with the schema.

| file | sha256 of the committed bytes (LF) |
|---|---|
| `maasspec_spectrum.schema.json` | `5f6f0048a284ed4ebd38baf78b105e473ee2c0418481e236ed466ba2ad3a1a2e` |
| `maasspec_fixture.spectrum.json` | `b3241483bfcfb669d94f88d2b30a8f675c534ce8075dd6cd97ec73190744cd89` |
| `maasspec_spectra.json` | `2c2caa364d5326ae57e77815358cb4684ffda0febe30a1b8837c258c022baff9` |
