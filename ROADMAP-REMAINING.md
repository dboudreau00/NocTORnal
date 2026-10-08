# What is left

**State (2026-10-08):** branch `main`, Alembic head `0182`,
8365 tests counted as `def test_` functions across the two pytest roots,
version 0.9.1 single-sourced from `pyproject.toml`. Those four counters are
generated: `scripts/refresh_counters.py` writes them and `test_doc_invariants`
holds them to the tree with no tolerance. Per-release totals of COLLECTED
items, which parametrisation makes larger, are in `release/CHANGELOG.md`.
Beta 1.1 (2026-10-08) is released. **Every roadmap item is built.** The
end-to-end check of the Telegram adapter is `scripts/telegram_live_check.py`,
which an operator runs with the deployment's own Telegram account (docs/17
F31). What stands between the product and a deployment is not software: it is
the five legal items L1 to L5 (docs/16).

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

Every phase has all four. What is left in a phase is feature work.

### Per phase

The percentages are the Alpha 6 scores. The work built since is listed under
"What was built, by release" and is not rescored, so a row can read "nothing
left" beside a figure below 100.

| Phase | Complete | Model+tests | API | UI | Reviewed | What is left |
|---|---|---|---|---|---|---|
| 0, Foundation | **100%** | ✅ | ✅ | ✅ | ✅ | Nothing. No typecheck, deliberately (decision 42). |
| 1, Graph core | **100%** | ✅ | ✅ | ✅ | ✅ | Nothing. |
| 2, Sociogram | **100%** | ✅ | ✅ | ✅ | ✅ | Nothing. |
| 3, Analytics | **85%** | ◐ | ✅ | ◐ | ✅ | Nothing named. Conversations are projected only by the Comms pane's co-participation view, deliberately (decision 73). Regular equivalence (REGE) sits beside CONCOR. |
| 4, Collection | **90%** | ◐ | ✅ | ✅ | ✅ | Nothing named. The Telegram end-to-end check is an operator item (docs/17 F31). `run_once` raises no proposals, which is a decision recorded at the `Adapter` docstring and not a gap. |
| 5, Notification | **92%** | ✅ | ✅ | ◐ | ✅ | Nothing named. A receiver still on webhook signature v1 stays replayable (docs/07). |
| 6, Tradecraft | **96%** | ◐ | ✅ | ✅ | ✅ | Nothing named. WebAuthn is a deliberate absence, stated in four documents; SECURITY.md says reporting it is not a finding. |
| 7, Comms | **95%** | ✅ | ✅ | ✅ | ✅ | Nothing named. |
| 8, Samples | **80%** | ✅ | ✅ | ✅ | ✅ | Nothing named. **The one phase where 100% would still mean "do not switch on": see L1.** |
| 9, Ingest | **90%** | ✅ | ✅ | ✅ | ✅ | Nothing named. A vendor answer a lookup adapter cannot read is kept as UNREADABLE (docs/17 F27). |

### Overall: **92.8%**

The unweighted mean across the ten phases: 100, 100, 100, 85, 90, 92, 96, 95,
80, 90. This file is the only place the figure is worked out. Every other
document quotes it, and `test_doc_invariants` holds the quotations to this
line. It is the Alpha 6 figure; the work built since is not rescored here.

Two things the number does not say.

1. **Completion is not lawfulness.** A phase at 100% here may still be
   unlawful to operate. Phase 8 must not be switched on until L1 is settled.
   That is the point of the register below, not a caveat on the number.
2. **It is a measure of reach and scrutiny, not of scale.** The load figures
   are in docs/17, "Load and performance".

---

## What was built, by release

`release/CHANGELOG.md` says what each release contains and `docs/00-decisions.md`
says why. This is the index of the roadmap items.

**Alpha 7 (2026-09-25).** F1 CONCOR (decision 88), F2 one-mode projection
(73), F3 and F4 XenForo and MyBB (129 to 133), F5 Telegram (69, 134 to 136),
F6 document embeddings (116 to 120), F7 Jira (122), F8 the delivery ledger
(121), F9, F9b and F9c the two-person policy (90 to 95), F10 comms (112 to
115), F11 fuzzy hashing (96 to 100), F12 YARA (97, 101, 102), F13
prohibited-content screening (124 to 126), F14 the sandbox (127, 128), F15 the
outbound credential vault (75, 123), L1 to L6 (78, 80 to 83, 87), S1
row-level security (76, 137 to 151) and S2 the egress proxy (68, 72, 77, 84,
107 to 111; docs/20). Alpha 7a (2026-09-30) is in the changelog's own
section, and there was no Alpha 8 release.

**Beta 1 (2026-10-07).**

- **F51**, row-level security on every case table: 82 tables, none deferred
  (decisions 76, 137 to 163; docs/17 F51).
- **F52**, the cron jobs and a published credential: the schema owner's
  password is out of the runtime services, and every job script refuses a
  credential the repository publishes (`release/secrets-upgrade/README.md`).
- **Redis isolation, enforced**: an ACL with the default user off; the limiter
  signs in as `noctornal_limiter` and touches `rl:*` keys only.
- **A collector process** (decision 174): the persona key is held by the
  `collector` service alone, and the API queues persona acts for it.
- **F42**, the isolated analysis worker: static triage, archive expansion,
  watch patterns and forum parsing in a container with no secrets and no
  network.
- **REGE**, regular equivalence beside CONCOR, with caps calibrated to the
  measured cost (docs/03).
- **Archive expansion**, with named caps (docs/11, decision 178).
- **The authenticated forum path** under a MEMBER_READ authority (docs/16 L3),
  and **F43**, compartments on collection sources.
- **F31**, the Telegram end-to-end check an operator runs with the
  deployment's own account, with a dry run that proves the gates first.
- **F28, F30, F35, F36, F37, F39, F47** and owner question 11 (decisions 164
  to 173): webhook signature v2, the document sweep, a persona's exit at
  creation, typed ids in warnings, gpg fingerprints, the merge switch's second
  person, watches, and undated claims dated by supersession.
- **The 2026-10-03 review** kept 82 findings (16 high, 25 medium, 41 low, none
  critical), all fixed or stated: 77 fixed, one fixed for credentials and
  stated for the rest, and four stated and not fixed. docs/17, "The
  2026-10-03 review at Beta 1.1", lists each by area with its status.

**Beta 1.1 (2026-10-08).**

- **The request role narrowed** (Alembic 0174 to 0182; decisions 208 to 215): no
  session token or binding, no break-glass justification and no sealed column
  outside the accounts table is readable; no configuration table or delivery
  setting is writable; an exhibit and a case are updated only in the columns
  their routes write; a state-bearing audit row names a case; a request raises
  only the product's own notices.
- **Holds in the console** (decision 217): an exhibit's card and the case header
  place and lift a legal hold, and the hold's answer says what a purge destroyed
  while it waited.
- **Watches from the console and the API** (F53, decision 228): a collection
  manager assigned to a case adds a watch.
- **The sweep widened** (F55, decision 204): dead letters and ingest records
  attached to no case join the operator-run sweep.
- **A statement timeout on request connections; ego and path built from the
  centre** (decisions 221 and 222).
- **A real purge, a report and a report's release** follow the case's disclosure
  setting and the destination's configured ceiling (decisions 218 and 219).
- **Upload bounds, console compression, the hop-count readiness row and the
  pins** (decisions 223 to 225).
- **The owner's four answers** (decisions 202 to 205), recorded in docs/17,
  Decisions the owner took.
- **The 2026-10-03 review's residuals**: of its 82 findings, 78 are fixed, one is
  fixed apart from case membership and three are stated and not fixed. docs/17
  has each, and its Closed index has what Beta 1.1 closed.

---

## Before anything else: the legal register

`docs/16-legal-and-external.md` holds **5 blocking items, 12 determinations and
19 things to confirm externally**, and `docs/18-legal-review-pack.md` is the
version to hand to counsel, organised by what has to be decided and in what
order. The five blockers, compressed:

| | What | Why it blocks |
|---|---|---|
| **L1** | Prohibited-content policy for samples | The build refuses ingest until a policy reference and a designated person are declared, but that is a declaration it records, not one it can verify. `REJECTED` preserves the bytes under a legal hold by default (decision 61; docs/17 F2) and destroys them only where the deployment declares it. Screening holds no hash list until the authority to hold one is recorded. Whether this jurisdiction wants preservation, and for whom, is still counsel's. |
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

What the request role can still reach, and the other gaps the fixes and the
release reviews found and left, are in docs/17, "Known residuals at Beta 1.1".

---

## What remains open

**The Telegram end-to-end check (F31).** `scripts/telegram_live_check.py`
signs the operator in as the console does, checks the egress proxy, the
authority and the three routes, enrols the persona, makes one read-only poll,
reads the persona's membership of a member chat and logs the session out, and
prints one line per step. `--self-check` proves the gates and the shape of the
transcript first, connecting to nothing. An operator runs it with the
deployment's own Telegram account.

**Named and not built.** None of these is a roadmap feature: each waits on a
decision, or is hardening that needs a migration.

- Filtering `iam.case_assignment` for the request role. 31 code paths read
  the table, some on connections bound to nobody, so each needs a definer
  function before a row policy can stand on it (docs/17, Known residuals at
  Beta 1.1).
- The request role's last writes: the collector's heartbeat, the queues
  `core.embedding_pending`, `lab.yara_compile_job` and `ingest.batch`, and a
  case's retention date and governance text. Each needs a migration (docs/17).
- A way to stop or edit a watch. A watch is made from the console and the API
  and has no verb after that (docs/17, Known residuals at Beta 1.1).

**Records written under older rules** are listed and never filled or moved
(decision 80). Claims accepted from Triage with no observation date are dated
by supersession (the inspector's Date this claim) and are listed by
`scripts/legacy_records.py` and shown on the readiness register until they
are. ATTRIBUTE claims readable below their material or attached across cases
are listed too, and are retracted by an analyst.

**Legal blocks.** L1 to L5 in docs/16, above. Nothing here changes them.

---

## Open questions for the owner

None of the numbered questions is open (docs/00 questions 11 and 12, settled
by decisions 170 and 169). Judgements in docs/17 wait on the owner: who runs
the sweep of documents, dead letters and caseless ingest records, and under
which authority (F30, with counsel); how a co-participation weight divides;
whether a case's closure should look for a conversation nobody on the team
can minimise; whether a missing id should cost the same as a hidden one;
whether the lab keeps a copy of a sample per label set (lab-6); and whether
lifting a hold takes two people. The owner answered four others on 2026-10-08
(decisions 202 to 205): compartmented sources keep being polled, a sample
download is not an egress, dead letters join the sweep, and a retirement over
a hidden tie reads like any other refusal under NONE.

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

Each of these fails far from its cause or reads as a different problem.

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
  its case, or the user named on the custody row.
- **Teardown order follows the foreign keys, not the reading order.**
- **`NOT IN (subquery)` silently deletes nothing when the subquery yields a
  NULL.** Use `NOT EXISTS`.
- **`array_length('{}', 1)` is NULL, not 0.** Any `>= 1` check on an array
  needs `coalesce`, or it passes on the empty case.
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
  `screenshot_ui.py` refuses an un-ignored directory inside the repository.
- **gpg-agent does not autostart on this host** (`gpgconf --launch
  gpg-agent`), and the Windows `gpg` on PATH is the MSYS build shipped with
  Git, which expects POSIX paths: handed `C:\...` it resolves against its own
  cwd and reports a good key as unreadable. `pgp.py` passes relative paths
  with an explicit `cwd` for that reason. Do not tidy them into absolutes.
- **`docker exec` does not inherit a variable exported by the entrypoint.**
  Read `/proc/1/environ`, or pass `-e`.
- **A locale can hide a security defect.** The PGP status-injection flaw was
  live under UTF-8 and inert under this host's cp1252, so the development
  machine and CI disagreed about whether the system was exploitable. Where a
  defence depends on how bytes decode, assert on the bytes.

**Documents**

- **Check the claim, not just the code.** A docstring that states a fact is a
  claim: write the sentence down and go and check it. The dead-letter
  redactor's docstring said the verbatim bytes remained in the batch's raw
  object, and no caller stored them.
- **A generator loose in prose destroys the records it walks past.**
  `refresh_counters.py` prints every line it changes, and the shapes it
  matches are deliberately narrow.
- **A counter written in a shape nothing checks drifts exactly as far as one
  nobody checks.** Write a live figure in one of the shapes the generator
  holds, or do not write it.
