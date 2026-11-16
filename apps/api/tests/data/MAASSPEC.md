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

| file | sha256 |
|---|---|
| `maasspec_spectrum.schema.json` | `5b356227e86ceffee139f4ce830836f6f4d63172a9bab5a8bc1ee4cda0a38185` |
| `maasspec_fixture.spectrum.json` | `ba7c1c6468e5380e645640691f52f15f9fc783a7dbf229708d4dce6e9189abd3` |
| `maasspec_spectra.json` | `6700319c19e3e018738c40e5d80e9edeb1fd0e8737d258d8d9d1e73550723c4f` |
