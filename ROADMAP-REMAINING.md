# What is left

**State (2026-10-07):** branch `main`, Alembic head `0173`,
7966 tests counted as `def test_` functions across the two pytest roots,
version 0.7.1 single-sourced from `pyproject.toml`. Those four counters are
generated: `scripts/refresh_counters.py` writes them and `test_doc_invariants`
holds them to the tree with no tolerance. Per-release totals of COLLECTED
items, which parametrisation makes larger, are in `release/CHANGELOG.md`.
Alpha 7 (2026-09-25) released every roadmap feature (F1 to F15), every
leftover Alpha 6 named (L1 to L6), the egress proxy (S2) and row-level
security (S1). Beta 1 (2026-10-07) carries everything since Alpha 7a: the
part of the build that had merged when work stopped on 2026-10-03 (there was
no Alpha 8 release), and all that was built after. Row-level security now
stands on 82 tables and defers none (F51), the persona vault is split into a
collector process (decision 174), hostile bytes are parsed in an isolated
worker (F42), the schema owner's password is out of the runtime services and
Redis runs under an ACL (F52), and REGE, archive expansion, the authenticated
forum path and compartments on collection sources (F43) are built, with the
fixes for the 82 findings of the 2026-10-03 review. **Every roadmap item is
built except one, F31:** a first run of the
Telegram adapter against Telegram itself. Only the owner can close it, with
their own account, by running `scripts/telegram_live_check.py` (docs/17 F31).

This file is what is left. What was done and when is in the changelog; what is
known-wrong is in `docs/17-flagged-for-review.md`; what is blocked on somebody
outside the code is in `docs/16-legal-and-external.md`.

---

## Scoreboard

### How the numbers are calculated

A phase is finished when somebody can use it and trust it, not when its
service code exists, so completion is weighted across four dimensions.

| Dimension | Weight | Done means |
|---|---|---|
| **Model, service and tests** | 45% | Schema, service logic, migrations that round-trip, tests named for the invariants they protect |
| **HTTP API** | 15% | Routed, gated by the five-part access check, rate-limited |
| **Analyst UI** | 25% | Reachable and usable in the browser, not only by `curl` |
| **Adversarial review** | 15% | A hostile pass with findings reproduced before being acted on |

Every phase now has all four. The recurring gap is feature work, not reach or
scrutiny.

### Per phase

The percentages are the Alpha 6 scores. The work built since is named in each
row and is not rescored here, so a row can read "nothing left" beside a
figure below 100: the score waits for the owner. The work released in Alpha 7
and Beta 1 has had the 2026-10-03 review, which kept 82 findings that are all
fixed or stated (docs/17), an independent re-verification of the fixes and
nine release reviews. Those are not repeated in each row.

| Phase | Complete | Model+tests | API | UI | Reviewed | What is left |
|---|---|---|---|---|---|---|
| 0, Foundation | **100%** | ✅ | ✅ | ✅ | ✅ | Nothing. No typecheck, deliberately (decision 42). |
| 1, Graph core | **100%** | ✅ | ✅ | ✅ | ✅ | Nothing. |
| 2, Sociogram | **100%** | ✅ | ✅ | ✅ | ✅ | Nothing. |
| 3, Analytics | **85%** | ◐ | ✅ | ◐ | ✅ | Built since Alpha 6: CONCOR roles (F1), forums and wallets projected to entities (F2), an accepted-ties-only scope (L3) and, since Alpha 7a, REGE regular equivalence beside CONCOR (docs/03). Left: nothing named; conversations are projected only by the Comms pane's co-participation view, deliberately (decision 73). |
| 4, Collection | **90%** | ◐ | ✅ | ✅ | ✅ | Built since Alpha 6: the collection foundation with the two-person collection authority, XenForo and MyBB (F3, F4), Telegram over MTProto (F5) and document embeddings (F6). Built since Alpha 7: an operator-run sweep of collected documents past their clock (docs/17 F30), watches on forum signatures and Telegram chats (F47), a persona refused at creation on a profile that cannot carry persona traffic (F35), a typed Telegram id kept in a run's warnings (F36), and Telegram chats under row-level security. Built since Alpha 7a: the authenticated forum path (a member read under a MEMBER_READ authority), compartments on collection sources (F43), the persona vault split into a collector process (decision 174) and a test of a persona's run, act and stop through the real egress listener. Left: a first run against Telegram itself (docs/17 F31), which only the owner can make. `run_once` raises no proposals, which is a decision recorded at the `Adapter` docstring rather than a gap. |
| 5, Notification | **92%** | ✅ | ✅ | ◐ | ✅ | Built since Alpha 6: Jira (F7) and the delivery ledger's screen under Administration, Integrations (F8), and the egress proxy that every delivery now leaves through (S2). Built since Alpha 7: notifications under row-level security, raised through one definer function, and an opt-in v2 webhook signature with a timestamp (docs/17 F28). Left: nothing named; a receiver still on v1 stays replayable (docs/07). |
| 6, Tradecraft | **96%** | ◐ | ✅ | ✅ | ✅ | Built since Alpha 6: the two-person policy screen (F9), a case's merge switch that takes two people to turn off (F9b), and the retirement of the dead dual-control columns (F9c). Built since Alpha 7: the switch's second person must have held `case.update` for a window the deployment sets (F39), and an undated legacy claim is dated by supersession (docs/00 decision 170). Left: nothing named. WebAuthn is a deliberate absence, stated in four documents; SECURITY.md says reporting it is not a finding. |
| 7, Comms | **95%** | ✅ | ✅ | ✅ | ✅ | Built since Alpha 6: detached signatures, subkey signatures confirming the primary, a vendor key registry and two-person Web Key Directory lookups (F10). Built since Alpha 7: gpg's double-spaced fingerprint display parses in a contact block (docs/17 F37). Left: nothing named. |
| 8, Samples | **80%** | ✅ | ✅ | ✅ | ✅ | Built since Alpha 6: static triage with imphash, Rich header, ssdeep and TLSH (F11), YARA rule sets (F12), exact-hash prohibited-content screening (F13) and sending to a self-hosted CAPEv2 (F14). Built since Alpha 7a: archive expansion (docs/11) and the isolated analysis worker, a container with no secrets and no network (F42). Left: nothing named. **The one phase where 100% would still mean "do not switch on": see L1.** |
| 9, Ingest | **90%** | ✅ | ✅ | ✅ | ✅ | Built since Alpha 6: the outbound credential vault with per-provider quota, exposure levels and a colleague's sign-off (F15), and the `duplicate_of` index (L4). Built since Alpha 7: the lookup ledger under row-level security. Built since Alpha 7a: the ingest record family under row-level security (F51). Left: a sweep for dead letters and ingest records attached to no case (docs/17 F55); no lookup adapter has met its live service (docs/17 F27). |

### Overall: **92.8%**

The unweighted mean across the ten phases: 100, 100, 100, 85, 90, 92, 96, 95,
80, 90. This file is the only place the figure is worked out. Every other
document quotes it, and `test_doc_invariants` holds the quotations to this
line, because quoting is what drifted: three documents once carried three
different numbers. It is the Alpha 6 figure: the work above, released in
Alpha 7 and Beta 1, is not rescored here.

Two things the number does not say.

1. **Completion is not lawfulness.** A phase at 100% here may still be
   unlawful to operate. Phase 8 must not be switched on until L1 is settled.
   That is the point of the register below, not a caveat on the number.
2. **It is a measure of reach and scrutiny, not of scale.** Nothing here has
   run against a real case, on real volume, for a real unit.

---

## What the roadmap after Alpha 7 became

Everything below is built and released in Beta 1, and the changelog's Beta 1
section says what each does. docs/00 decisions 152 to 201 record why; there
was no Alpha 8 release, and the part of this table that its draft described
was built first.

| Item | What it became | Where |
|---|---|---|
| **F51** Row-level security, to every case table | Notifications raised through one definer function and read by their recipient alone; the lookup ledger at its own labels; Telegram chats at their source's label; then the ingest record family and the audit log, whose readers moved to definer functions and named system purposes, and the persona act queue. 82 tables under policy, none deferred | `notifications.py`, `lookups.py`, `providers.py`, `telegram_service.py`, `rls_registry.py`, Alembic 0125 to 0129, 0152 to 0156 and 0166 to 0169 (decisions 152 to 163, 151) |
| **F52** The owner's credential out of the runtime services | `POSTGRES_PASSWORD` and the migration connection string in `postgres-init.env` and `migrate.env`, each read by one service; the API and every cron job refuse to hold either; one refusal for a published credential in every job script | `scripts/migrate_job.py`, `scripts/production_secrets.py`, `config.py`, `release/secrets-upgrade/README.md` |
| **Redis isolation** | An ACL with the default user off; the limiter signs in as `noctornal_limiter` and may touch `rl:*` keys only | `infra/production/compose.yml`, `ratelimit.py` |
| **Decision 174** The collector process | The persona key held by the `collector` service alone; the API queues persona acts in a table and the collector runs them and every scheduled poll; a heartbeat and the readiness row `collector_split` | `scripts/collector.py`, `persona_acts.py`, Alembic 0156, 0157, 0165 |
| **F42** The isolated analysis worker | Static triage, archive expansion, watch patterns and forum parsing run in a container with no secrets and no network, one child per request, each under a uid of its own | `analysis_worker.py`, `analysis_runner.py`, `infra/production/README.md` |
| **REGE** | Regular equivalence beside CONCOR, with caps calibrated to the measured cost | `rege.py`, `GET /cases/{id}/analytics/rege` (docs/03) |
| **Archive expansion** | Zip, OOXML, tar and compressed tar walked in a child; each member a screened sample; named caps, including 1,000 members in a tree | `lab_archive.py`, `lab_archive_child.py`, Alembic 0158 to 0160 (docs/11, decision 178) |
| **The authenticated forum path** | XenForo and MyBB read as a signed-in persona under a MEMBER_READ authority; the session sealed beside the credential; every post says MEMBER | `forum_member.py`, `forum_session.py`, Alembic 0161, 0162 |
| **F43** Compartments on collection sources | A source carries compartments and so does every document it collects | `collection.py`, Alembic 0163, 0164 |
| **F31** The Telegram first run | The owner's script, with a dry run that proves the gates before the account is spent. **Not run: only the owner can.** | `scripts/telegram_live_check.py` |
| **The 2026-10-03 review** | 82 findings fixed or stated, the fixes re-verified by seven readers, then nine release reviews (install, workflows, load, authorization, evidence and egress, collection and the Lab, upgrade, deployment, code quality) | docs/17, the changelog's review section, Alembic 0132 to 0151, 0171, 0172 and 0173 |
| **F35** A persona's exit at creation | Refused at creation on a profile that cannot carry persona traffic, in the egress proxy's sentence | `collection.py` (decision 164) |
| **F36** Typed ids in warnings | The ids the adapters write are kept in a run's item label; every other id is still redacted | `collection.py` (decision 165) |
| **F37** gpg fingerprints | Whole hex groups kept on `PGP_FPR` lines; parser version cb-2 | `contact_blocks.py` (decision 166) |
| **F28** Webhook signature v2 | An opt-in signature with a timestamp, and no v1 header beside it | `transports.py`, docs/07 (decision 167) |
| **F47** Watches | A forum post's signature matched with reasons of its own; a Telegram chat as a watch's target | `collection.py`, Alembic 0130 (decision 168) |
| **F39** The switch's second person | Must have held `case.update` on the case for `NOCTORNAL_RELAX_SEASONING_DAYS` days, 7 by default | `approvals.py` (decision 169) |
| **Owner question 11** Undated claims | Dated by supersession, never by writing onto a recorded claim; invariant 5 not amended | `graph.py`, Alembic 0131 (decision 170) |
| **F30** Document sweep | An operator-run sweep of collected documents past their clock, dry by default, under a declared authority | `scripts/retention_sweep.py`, `retention_sweep.py` (decisions 171 to 173) |

---

## What the roadmap after Alpha 6 became

Everything below is built and was released in Alpha 7, and the changelog's
Alpha 7 section says what each does. docs/00 decisions 68 to 136 record why.

| Item | What it became | Where |
|---|---|---|
| **F1** CONCOR | Roles by CONCOR, one to four splits, as a card in the Analysis pane; numpy held to one BLAS thread per process | `blockmodel.py`, `GET /cases/{id}/analytics/concor` (decision 88) |
| **F2** One-mode projection | Forums and wallets projected to ties between entities, per run, derived and never stored or drawn; conversations deliberately not | `affiliation.py` (decision 73) |
| **F3, F4** XenForo and MyBB | Public threads and boards, under a collection authority, through the source's own exit, parsed in a bounded child | `forum_adapters.py`, `forum_parse.py`, Alembic 0104 (decisions 129 to 133) |
| **F5** Telegram | MTProto monitoring with Telethon, behind the authority, the egress proxy and the AMBER ceiling; the collection foundation it shares with the forums (F5.1) | `telegram.py`, `telegram_service.py`, `telegram_wire.py`, `scripts/telegram_persona.py`, Alembic 0081 to 0083, 0105 to 0107 (decisions 69, 134 to 136) |
| **F6** Document embeddings | Similar wording on this host, similar meaning through an operator's model server, over documents, exhibits and claims | `embedders.py`, `embeddings.py`, `scripts/embed_pass.py`, Alembic 0091 to 0094 (decisions 116 to 120) |
| **F7** Jira | An opt-in notification channel to one declared destination | `jira.py`, Administration, Integrations, Alembic 0097 (decision 122) |
| **F8** Delivery ledger | A cause and the exposure that left for every delivery, on a screen of its own | Administration, Integrations, Alembic 0095, 0096 (decision 121) |
| **F9, F9b, F9c** Dual control | The two-person policy screen; the case merge switch; the dead columns retired | `dual_control.py`, Administration, Two-person controls, Triage, Dual control, Alembic 0074 to 0077 (decisions 90 to 95) |
| **F10** Comms | Detached signatures, the vendor key registry, Web Key Directory lookups | `pgp.py`, `pgp_keys.py`, Alembic 0087 to 0090 (decisions 112 to 115) |
| **F11** Fuzzy hashing | Static triage in bounded children: imphash, Rich header, ssdeep, TLSH, similar samples | `lab_triage.py`, `lab_static.py`, `fuzzyhash.py`, `scripts/lab_triage.py`, Alembic 0078, 0079 (decisions 96 to 100) |
| **F12** YARA | Labelled, versioned rule sets activated by an officer who did not sponsor them | `yara_rules.py`, Lab, Rules, Alembic 0080 (decisions 97, 101, 102) |
| **F13** Prohibited-content screening | Exact md5, sha1 and sha256 against imported lists; a match leaves the Lab for good | `screening.py`, `scripts/sample_screen.py`, Alembic 0102 (decisions 124 to 126) |
| **F14** Sandbox | Sending to one self-hosted CAPEv2, with a second person's sign-off where the target or route is exposed | `sandbox.py`, `sandbox_capev2.py`, `scripts/sandbox_dispatch.py`, Alembic 0103 (decisions 127, 128) |
| **F15** Outbound credential vault | Lookup providers, sealed keys, an exposure ladder, a colleague's sign-off, quotas, batches | `providers.py`, `lookups.py`, `lookup_adapters.py`, `scripts/lookup_drain.py`, Alembic 0098 to 0101 (decisions 75, 123) |
| **L1** Compartments on collected documents | A capture stores its case's compartments, and every reader checks them | Alembic 0070, 0071 (decision 78) |
| **L2** Pre-Alpha-6 remediation | Legacy Triage claims and unlabelled captures are listed, never filled or moved | `scripts/legacy_records.py`, the readiness register (decision 80) |
| **L3** Reviewed ties only | An accepted-ties-only analysis scope | `projections.py` (decision 87) |
| **L4** `duplicate_of` index | A partial index, built in the migration | Alembic 0072 (decision 83) |
| **L5** Fragment identity | `url_norm` keeps a fragment only where it names the resource, never a key or a login token | `normalisers.py` (decision 81) |
| **L6** Retention rationale wording | The two seeded rationales no longer cite design documents | Alembic 0073 (decision 82) |
| **S2** The egress proxy | The only way out of production: one client, one address policy, persona and integration routes, a connection ledger | `egress_proxy.py`, `egress_routes.py`, `egress_policy.py`, `pinned_http.py`, `scripts/egress_setup.py`, Alembic 0085, 0086, docs/20 (decisions 68, 72, 77, 84, 107 to 111) |
| **S1** Row-level security | On 66 tables at Alpha 7, 82 since Beta 1 (above): requests read through policies as `noctornal_app`, whose IAM plane is read-only; work that must see every row runs as a named system purpose on `noctornal_worker`; each request's connection is bound to its session by a proof. None is deferred (docs/17 F51) | Alembic 0108 to 0124, `rls_registry.py`, `db.py`, `scripts/runtime_roles.py` (decisions 76, 137 to 151) |

---

## Before anything else: the legal register

`docs/16-legal-and-external.md` holds **5 blocking items, 12 determinations and
19 things to confirm externally**, and `docs/18-legal-review-pack.md` is the
version to hand to counsel, organised by what has to be decided and in what
order. The five blockers, compressed:

| | What | Why it blocks |
|---|---|---|
| **L1** | Prohibited-content policy for samples | The build refuses ingest until a policy reference and a designated person are declared, but that is a declaration it records, not one it can verify. `REJECTED` now preserves the bytes under a legal hold by default (owner decision, 2026-09-22; docs/17 F2), and destroys them only where the deployment declares it. Screening holds no hash list until the authority to hold one is recorded. Whether this jurisdiction wants preservation, and for whom, is still counsel's. |
| **L2** | Stealer-log lawful basis, victim notification, real retention | Holding data about thousands of uninvolved people. 90 days is a placeholder somebody typed. |
| **L3** | Persona operation authority | The software will drive an account into a forum or a Telegram chat under a collection authority two people recorded. Whether you may is not a software question. |
| **L4** | Interception law and consent | Message capture, and Telegram chats read as a member. `provenance_class` records which kind it was; the authority is external. |
| **L5** | Active web capture authority | Fetching attacker infrastructure discloses the investigation, and entering any input into a phishing page, canary credentials included, may constitute unauthorised access. The schema refuses to record a submission without a written authority reference. Nothing is automated. |

The nineteen confirm-externally items include evidence-authenticity standards
(reasoned from the rule text, not from a practitioner), MinIO COMPLIANCE
semantics on your actual object store, the platform durable-identifier
mappings, which change, and where a stale mapping produces confident false
attribution, what the Telegram adapter assumes about Telegram, and that the
production network really has no route out but the egress proxy. The newest
determinations in docs/16 are which egress exit providers are acceptable
(D10), how long the connection ledger is kept (D11) and whether any model
server may receive case text (D12).

---

## Security items still deferred

| Item | Note |
|---|---|
| CI typecheck | No annotations to check against (decision 42). |
| WebAuthn | A deliberate absence: password and TOTP today. SECURITY.md says reporting it is not a finding. |

The six items this table carried at Alpha 8 (row-level security on five
tables, the schema owner's password in the runtime services, a collector
process, isolating the analysis children, Redis isolation enforced by an ACL,
and the cron jobs' check for a published credential) are built, and are rows
of the table above. What the request role can still reach, and the other gaps
the fixes and the release reviews found and left, are in docs/17, Known
residuals at Beta 1.

---

## What remains open

**The one roadmap item not built:** F31, a first run of the Telegram adapter
against Telegram itself. `scripts/telegram_live_check.py` is that run: it
signs the operator in as the console does, checks the egress proxy, the
authority and the three routes, enrols the persona, makes one read-only poll,
reads the persona's membership of a member chat and logs the session out, and
prints one line per step. `--self-check` proves the gates and the shape of the
transcript first, connecting to nothing. Only the owner can run it, with their
own test account. The adapter has still never met Telegram.

**Named and not built.** None of these is a roadmap feature: each waits on a
decision, or is hardening that needs a migration.

- A sweep for dead letters and ingest records attached to no case, which
  nothing destroys when their clock runs out (docs/17 F55).
- A route or console form that creates a watch (docs/17 F53).
- A console control to place or lift a legal hold on an exhibit or a case.
  Both are done through the API today (docs/17, Known residuals at Beta 1).
- Narrowing the request role further: the unpolicied configuration tables,
  the hold and purge columns and the sealed columns outside the accounts
  table each need a migration (docs/17).

**The 2026-10-03 review.** An adversarial review of the beta build at commit
718f92d kept 82 findings: 16 high, 25 medium and 41 low, none critical. All 82
are fixed or stated at Beta 1: 77 fixed, one fixed for credentials and stated
for the rest, and four stated and not fixed. docs/17, "The 2026-10-03 review
at Beta 1", lists each by area with its status, and release/CHANGELOG.md,
Beta 1, says what the re-verification and the nine release reviews found.

**Legal blocks.** L1 to L5 in docs/16, above. Nothing here changes them.

---

## Left from the 2026-09-22 review

The 2026-09-22 usability and code review found 229 verified problems, and
Alpha 6 closes all of them: 75 in the first fix pass, every critical among
them, and the other 154 before tagging (148 fixed, 5 already fixed on the
release candidate, and 1 finished after a review of that pass). Two
reviews of the fixes found 43 and then 50 more, all fixed. The seven gaps
the known-open list named are closed too (release/CHANGELOG.md, Alpha 6).

What was left after it is built since (L1 to L6, and owner question 11 in
Beta 1), and one thing stays an analyst's work:

- Claims accepted from Triage before Alpha 6 with no observation date are
  dated by supersession (the inspector's Date this claim) and are still
  listed by `scripts/legacy_records.py` and shown on the readiness
  register; ATTRIBUTE claims readable below their material or attached
  across cases are listed too, and are retracted by an analyst.

---

## Open questions for the owner

None of the numbered questions is open: both were settled on 2026-10-02
(docs/00 decisions 169 and 170). Judgements in docs/17 wait on the owner: who
runs the document sweep, and under which authority (F30, with counsel);
whether dead letters and caseless ingest records join it (F55); whether a
compartmented source should be polled at all, because collection's TLP checks
pass no compartments while F43 polls compartmented sources on purpose;
whether a sample download is an egress; and the first run of the Telegram
adapter, F31.

## Open questions for the operator

- **Ingest key holders.** Internal scripts only, or external partners? It
  changes the support and abuse model (docs/16 D6).
- **Expected ingest volume.** Above roughly 1M records a day the bucket needs
  a different storage tier.
- **Which sandbox targets count as private** for detonation exposure. A
  self-hosted CAPEv2 is declared by its operator, and several "private"
  vendor tiers still share hashes with partners (docs/16 D5).
- **Who is the security officer?** Break-glass refuses to grant while no
  active account holds `SECURITY_OFFICER`, the readiness register blocks
  on it, and collection authorities, YARA activations, screening and the
  two-person policy all need one.
- **Retention periods.** Six placeholder rules ship in migration 0032, and
  purge warns loudly on every one nobody has confirmed. No FORUM_POST or
  FORUM_MEMBER rule is seeded, and the connection ledger has none at all
  (docs/16 D11).
- **How large is an exhibit?** `NOCTORNAL_MAX_EVIDENCE_BYTES` must be declared
  before a production boot, because every accepted byte is locked under
  COMPLIANCE for the whole retention period (docs/08).
- **Which exits, lookup providers and model servers**, if any, this
  deployment may use (docs/16 D9, D10, D12).

---

## Traps worth carrying forward

Everything here cost somebody a session.

**Running the suite**

- **The test count is two roots**, `apps/api/tests` and `packages/ontology`.
  Run both or the number will not reconcile with this file.
- **`alembic` must be run from the repository root.** `alembic.ini` is there,
  not in `db/`, and running it from `db/` fails with "No 'script_location'
  key found in configuration", which reads as a broken install and is not.
- **`alembic downgrade base` succeeds on a clean database and stalls around
  0017 on a working one**, which has accumulated test data. CI runs the round
  trip on an empty database. To check the chain, use a scratch database and
  install the extensions first (`vector`, `pg_trgm`, `pgcrypto`,
  `btree_gist`, `citext`, `uuid-ossp`); without them the chain dies at 0004
  with "type vector does not exist", which reads as a migration bug and is
  not one.
- **Do not run two copies of the suite against one database at once.** The
  end-to-end cleanups delete by email pattern, so concurrent runs delete
  each other's fixtures and the failures look real.
- **uvicorn runs without `--reload`.** A new route 404s until restart.
- **TOTP codes are single-use.** Two sign-ins inside one 30-second step fail
  on the replay guard, not on the thing under test. Where the host clock is
  unsynchronised, `bootstrap.py session --email <you>` mints one directly.
- **The migration round-trip tests run first.** They migrate the database
  the rest of the suite uses, so `conftest.py` orders them ahead of
  everything else; a round trip run in the middle of a suite pulls tables
  out from under the tests around it.
- **A test connection handed to `route_for` must answer `execute` and
  `fetchone`.** The route provider reads the egress configuration from the
  database, so a stand-in connection that only records calls fails far from
  the code under test.
- **The host clock can step backwards** (a WSL clock resynchronising does).
  Never order by a timestamp in a test, and never assume `now()` moved
  forward between two statements.
- **Do not run two egress suites against one database at once.** They
  retire the live egress configuration and restore it afterwards, so two at
  once restore each other's half-way state.

**The database**

- **An append-only ledger outlives its subject, so teardown must skip it.**
  `lab.sample_access`, `core.evidence_custody`, `core.purge_tombstone` and
  `audit.event` all raise on DELETE and carry foreign keys to the thing they
  describe, so a test that ingests evidence can never delete that evidence,
  its case, or the user named on the custody row. Four suites learned this
  the same way.
- **Teardown order follows the foreign keys, not the reading order.**
- **`NOT IN (subquery)` silently deletes nothing when the subquery yields a
  NULL.** Use `NOT EXISTS`.
- **`array_length('{}', 1)` is NULL, not 0.** Any `>= 1` check on an array
  needs `coalesce`, or it passes on the empty case. This shipped as a real
  bug in the stealer-log compartment check.
- **A partial unique index needs its predicate restated in `ON CONFLICT`,**
  and **a unique index over nullable columns needs `coalesce`**: two NULLs
  never conflict, so the duplicate the index exists to prevent is inserted
  twice while the index looks like protection.
- **Constraints tie fields together and fire on UPDATE.** A case cannot be
  created already expired, a break-glass grant cannot be aged past eight
  hours, an ingest key cannot expire before it was issued. Age the pair.
- **Retention rules and the comms stoplist are global.** A test that confirms
  one leaks into every later test; the comms tests use a reserved
  `*.cbstop.test` domain so teardown can find the rows.
- **`iam.case_assignment.granted_by` is NOT NULL.**

**The console**

- **A CSS character class of literal invisible characters will be mangled**
  between writing it and it landing on disk. Declare them as `\uXXXX`
  escapes, which is also the only form a test can assert on.
- **`animation-fill-mode: backwards` plus a delay hides content** for the
  whole delay, and indefinitely if the animation clock stalls, which a hidden
  tab already causes here.
- **A hidden browser tab clamps `setTimeout` to about a second** and suspends
  `ResizeObserver`.
- **Always open a login change in a browser.** A sign-in that throws after
  the server has already signed the analyst in looks, from the suite, exactly
  like a sign-in that works.

**Tooling**

- **`--out` is not covered by `.gitignore` just because the default is.**
  `screenshot_ui.py` refuses an un-ignored directory inside the repository,
  after fifteen renders of a live case sat untracked in the working tree.
- **gpg-agent does not autostart on this host** (`gpgconf --launch
  gpg-agent`), and the Windows `gpg` on PATH is the MSYS build shipped with
  Git, which expects POSIX paths: handed `C:\...` it resolves against its own
  cwd and reports a good key as unreadable. `pgp.py` passes relative paths
  with an explicit `cwd` for that reason. Do not tidy them into absolutes.
- **`docker exec` does not inherit a variable exported by the entrypoint.**
  Read `/proc/1/environ`, or pass `-e`. This produced two false failures.
- **A locale can hide a security defect.** The PGP status-injection flaw was
  live under UTF-8 and inert under this host's cp1252, so the development
  machine and CI would have disagreed about whether the system was
  exploitable. Where a defence depends on how bytes decode, assert on the
  bytes.

**Documents**

- **Check the claim, not just the code.** The dead-letter redactor's
  docstring said the verbatim bytes remained in the batch's raw object, which
  is the whole reason redacting the fragment is safe rather than lossy. It
  was false: `accept()` stored the payload only when given a storage adapter,
  and every caller passed none. The defect was found by writing the sentence
  down and then going to check it.
- **A generator loose in prose destroys the records it walks past.** The
  first run of `refresh_counters.py` rewrote two dated figures it was never
  meant to touch. It prints every line it changes for that reason, and the
  shapes it matches are deliberately narrow.
- **A counter written in a shape nothing checks drifts exactly as far as one
  nobody checks.** This file's own state paragraph wrote its total as
  ``1565 `def test_` functions``, which the checker could not see, and it
  drifted two hundred tests while every other document was held exactly.
