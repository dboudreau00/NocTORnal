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
- **Nothing dropped.** `build` compiles each file (with yara-x, the product's
  own engine, when `noctornal-api[yara]` is installed) and routes
  non-compiling files to `dist/dead_letter.json` with the reason,
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
  `sources.json`. Add rule repositories only.
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

`build` compiles with the product's own engine and two-pass compile when
yara-x is installed (`noctornal-api[yara]`), so a file that fails there is a
file that contributes no rule in the product either; without it the index
still lists every rule and its source, with `compiles` left null.

```bash
python scripts/yara_db.py import --only bartblaze-yara \
    --classification AMBER --compartments KEY1,KEY2
```

`import` stores each named source in the deployment's database as a new
version of a rule set of the same name (created if absent), with the licence
and review flag from `sources.json` and the commit from `fetch.lock.json`,
recorded as imported by this script on this host. **It never activates
anything.**

## How it plugs into the Lab

Since 2026-09-24 (roadmap F12) rule sets live in the product, in the Lab's
**Rules** tab:

1. A lab member (`sample.yara.manage`) creates a labelled rule set and
   uploads a version: a `.yar`/`.yara` file or a `.zip` of them, with its
   licence. An imported version must be **adopted** by a lab member first.
2. A Security Officer (`sample.yara.activate`), who may not be the version's
   sponsor, activates it from Oversight, writing down the licence clearance
   when the source asks for review.
3. Static triage scans each sample with every active version, in a limited
   child process, and records a machine finding per version: which rules
   matched, their metadata, and pattern offsets and counts. Never the
   matched bytes.

The two hard constraints still hold, and the code enforces them:

1. **Samples never render or execute (invariant 10).** Matching is static
   pattern-matching over bytes decrypted in memory; nothing is rendered or
   run, and the download rule is untouched.
2. **A YARA hit is not a fact (invariant 1).** A match is a machine finding
   about the sample, read through the rule set's labels; a family reaches a
   case only as an analyst's assessment with a confidence.

Each file compiles on its own first, and a file with any error (a
cross-file reference, an include, an unknown identifier) contributes no
rule; the build report names the file, line and error code.
