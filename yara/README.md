# YARA detection corpus

A curated, provenance-tracked YARA ruleset pulled from public sources, feeding
the Phase 8 sample-triage layer (`apps/api/src/noctornal_api/samples.py`,
schema `lab`). It is built the way the rest of NocTORnal treats every ingested
artifact: each rule traces to a source and a commit, nothing that fails to
compile is silently dropped, and licences are explicit.

## Design

- **Not bundled.** The rules themselves are pulled into `vendor/` and compiled
  into `dist/`, both gitignored. Only the manifest (`sources.json`), the tool
  (`../scripts/yara_db.py`), this README, and the provenance lock
  (`fetch.lock.json`) live in git. A prosecution-grade tool must not silently
  inherit the licence of every third-party rule by committing it; the corpus is
  a build artifact, fetched on demand.
- **Provenance.** `fetch.lock.json` records, per source, the exact commit
  pulled and when. Reproducible, and auditable in a disclosure context.
- **Nothing dropped.** `build` compiles each file (if `yara-python` is present)
  and routes non-compiling files to `dist/dead_letter.json` with the reason,
  rather than dropping them (mirrors invariant 12). Rule-name collisions across
  sources go to `dist/collisions.json`, not a silent last-writer-wins merge.
- **Licences vary.** Every source flagged `"review": true` in `sources.json`
  must be cleared before any redistribution or commercial use. Some (e.g.
  `signature-base`, `elastic-protections`) carry non-permissive terms.

## Safety: rules only, kept off the cloud

Two hardening rules, both added after a pulled threat-intel/IOC repo
(`StrangerealIntel/DailyIOC`) shipped live FIN7 and Babuk samples that the
workstation's ESET quarantined mid-clone:

- **Rules only.** `fetch` prunes every file that is not `.yar`/`.yara` (keeping
  `.git` for updates) immediately after each clone, so no sample, dropper,
  script or document persists. Threat-intel/IOC dumps are excluded from
  `sources.json` — add rule repositories only.
- **Off the cloud.** Set `NOCTORNAL_YARA_HOME` to a path OUTSIDE any
  OneDrive/Dropbox/synced tree, and add an antivirus exclusion for it, before
  fetching. Live rules routinely contain malicious byte patterns as strings;
  an on-access scanner or a cloud sync watching that folder will fight the
  fetch. The default keeps `vendor/` inside the repo, which is safe only if the
  repo itself is not cloud-synced.

## Use

```bash
python scripts/yara_db.py fetch      # clone/update every source in sources.json
python scripts/yara_db.py build      # validate + index into yara/dist/
python scripts/yara_db.py stats      # provenance + counts
python scripts/yara_db.py fetch --only signature-base bartblaze-yara
```

`build` uses `yara-python` when installed (compile validation); without it the
index still lists every rule and its source, with `compiles` left null.

## How it will plug into Phase 8 (not yet wired)

The corpus is scaffolding today. Wiring it into `SampleService` triage is
Phase 8 work and carries two hard constraints from the invariants:

1. **Samples never render or execute (invariant 10).** YARA matching is static
   pattern-matching over bytes in the sample store; a match must not cause the
   sample to be rendered or run, and nothing about matching relaxes the
   separate-origin download rule.
2. **A YARA hit is not a fact (invariant 1 / decision: machines propose).** A
   match is evidence, graded and attributed to the rule and its source; it is
   written as a proposal / assertion for an analyst, never as ground truth on
   the sample.

Still to do: namespaced multi-file compilation (cross-rule references currently
fail per-file compile and land in the dead-letter), external-module coverage
(`pe`, `math`, `hash`, `dotnet`; `cuckoo`/`androguard`/`magic` are usually
absent), and a scan endpoint that records matches as gradeable assertions.
