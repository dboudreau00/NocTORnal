# What is left

**State (2026-09-23):** branch `main` (the working branch; byte-identical to
`deception-and-release-hardening` except `README.md`), Alembic head `0065`,
2518 tests counted as `def test_` functions across the two pytest roots,
version 0.5.2 single-sourced from `pyproject.toml`. Those four counters are
generated: `scripts/refresh_counters.py` writes them and `test_doc_invariants`
holds them to the tree with no tolerance. Per-release totals of COLLECTED
items, which parametrisation makes larger, are in `release/CHANGELOG.md`.

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

| Phase | Complete | Model+tests | API | UI | Reviewed | What is left |
|---|---|---|---|---|---|---|
| 0, Foundation | **100%** | ✅ | ✅ | ✅ | ✅ | Nothing. No typecheck, deliberately (decision 42). |
| 1, Graph core | **100%** | ✅ | ✅ | ✅ | ✅ | Nothing. |
| 2, Sociogram | **100%** | ✅ | ✅ | ✅ | ✅ | Nothing. |
| 3, Analytics | **85%** | ◐ | ✅ | ◐ | ✅ | CONCOR. Bipartite to one-mode landed for conversations only: actor×forum and actor×wallet still use two-mode presets, and `_mode_warning` says so. |
| 4, Collection | **90%** | ◐ | ✅ | ✅ | ✅ | XenForo, MyBB and Telegram MTProto adapters (each blocked on docs/16 L3 as much as on code), and document embeddings. `run_once` raises no proposals, which is a decision recorded at the `Adapter` docstring rather than a gap. |
| 5, Notification | **92%** | ✅ | ✅ | ◐ | ✅ | Jira, and an admin surface for the integrations: the `notify.delivery` ledger records every refusal with a reason and the address each message reached, and nothing renders it. |
| 6, Tradecraft | **96%** | ◐ | ✅ | ✅ | ✅ | The dual-control-policy surface (which operations require two people is configuration with no screen). WebAuthn is a deliberate absence, stated in four documents; SECURITY.md says reporting it is not a finding. |
| 7, Comms | **95%** | ✅ | ✅ | ✅ | ✅ | Optional only: detached signatures alongside clearsigned, and a keyserver-free way to obtain a vendor key. |
| 8, Samples | **80%** | ✅ | ✅ | ✅ | ✅ | Fuzzy hashing (imphash, ssdeep, TLSH), YARA, prohibited-content screening, sandbox integration. Each absence is recorded on the sample row as a gap with a reason, and the Lab pane renders the gaps before it renders any finding. **The one phase where 100% would still mean "do not switch on": see L1.** |
| 9, Ingest | **90%** | ✅ | ✅ | ✅ | ✅ | The outbound credential vault with per-provider quota and exposure levels. |

### Overall: **92.8%**

The unweighted mean across the ten phases: 100, 100, 100, 85, 90, 92, 96, 95,
80, 90. This file is the only place the figure is worked out. Every other
document quotes it, and `test_doc_invariants` holds the quotations to this
line, because quoting is what drifted: three documents once carried three
different numbers.

Two things the number does not say.

1. **Completion is not lawfulness.** A phase at 100% here may still be
   unlawful to operate. Phase 8 must not be switched on until L1 is settled.
   That is the point of the register below, not a caveat on the number.
2. **It is a measure of reach and scrutiny, not of scale.** Nothing here has
   run against a real case, on real volume, for a real unit.

---

## Before anything else: the legal register

`docs/16-legal-and-external.md` holds **5 blocking items, 8 determinations and
13 things to confirm externally**, and `docs/18-legal-review-pack.md` is the
version to hand to counsel, organised by what has to be decided and in what
order. The five blockers, compressed:

| | What | Why it blocks |
|---|---|---|
| **L1** | Prohibited-content policy for samples | The build refuses ingest until a policy reference and a designated person are declared, but that is a declaration it records, not one it can verify. `REJECTED` now preserves the bytes under a legal hold by default (owner decision, 2026-09-22; docs/17 F2), and destroys them only where the deployment declares it. Whether this jurisdiction wants preservation, and for whom, is still counsel's. |
| **L2** | Stealer-log lawful basis, victim notification, real retention | Holding data about thousands of uninvolved people. 90 days is a placeholder somebody typed. |
| **L3** | Persona operation authority | The software will drive an account into a forum. Whether you may is not a software question. |
| **L4** | Interception law and consent | Message capture. `provenance_class` records which kind it was; the authority is external. |
| **L5** | Active web capture authority | Fetching attacker infrastructure discloses the investigation, and entering any input into a phishing page, canary credentials included, may constitute unauthorised access. The schema refuses to record a submission without a written authority reference. Nothing is automated. |

The thirteen confirm-externally items include evidence-authenticity standards
(reasoned from the rule text, not from a practitioner), MinIO COMPLIANCE
semantics on your actual object store, and the platform durable-identifier
mappings, which change, and where a stale mapping produces confident false
attribution.

---

## Security items still deferred

| Item | Note |
|---|---|
| DNS-rebinding-proof SSRF protection | `fetch()` re-validates every redirect hop and classifies addresses by what they are rather than by an enumerated list, but the name is resolved once here and again by the socket layer. The real fix is a proxy enforcing policy at connect time. |
| RLS under the non-owner role | The production deployment connects as `noctornal_app`, which cannot disable the append-only triggers. Row-level security on top of that is not written. |
| CI typecheck | No annotations to check against (decision 42). |
| A collector process | The persona vault runs inside the API process, so invariant 7 is a property of the code's shape rather than of a network boundary. Splitting it out is behind L3 and a queue nothing has needed. |
| Compartment retirement | Every compartment column is bound to `iam.compartment` (0059), and no route deletes or renames a registered key while a row carries it. |
| Redis isolation | The limiter's meters need an instance running `noeviction`. The production compose sets it and the readiness register reports the policy, but whether the limiter has that instance to itself is a deployment fact the runtime cannot see. |

---

## Left from the 2026-09-22 review

The 42-agent usability and code review found 229 verified problems. The fix
pass that followed closed 75, every critical among them (release/CHANGELOG.md).
**154 remain: 25 high, 102 medium, 27 low.** The highs, by area:

| Area | What is still wrong |
|---|---|
| Triage (6) | Single-key and Ctrl shortcuts accept a proposal with no confirmation; the graph's "unreviewed proposals" count and the Triage queue disagree and nothing reviews the graph's; a notification's "Open approvals" opens the current case; a merge approval shows two UUIDs and no requester; contact-block proposals name no identifier; triage cards carry no TLP and Accept files selectors as AMBER whatever the capture was |
| ACH (5) | An unscored row reads as "settles nothing"; stance notes are never shown and are wiped on save; "refute this first" never appears; a hypothesis cannot be accepted, rejected, edited or removed; Cancel on withdrawing an assumption still withdraws it |
| Analytics (4) | The navigation budget runs out and disables Node size; results stay on screen after the graph or as-of time changes; "brokers" mislabels median-constraint actors; the trend plots run time, not as-of time |
| Feeds (3) | Dead letters hide the feed and have no replay; a watched-selector hit names no selector and scores every case's watches; queue and quarantine records cannot be acted on |
| Elsewhere (7) | Every tie reads "review PROPOSED"; the upload form cannot record when, where or under what authority an exhibit was obtained; a malware analyst cannot assign a sample or record findings from the console; compartment read-ins cannot be seen or set in Admin; at 200% zoom most projection controls are out of reach; single-letter triage keys fire from anywhere on the pane |

Found during the pass and not yet fixed:

- A `CLOSED` or `ARCHIVED` case still accepts writes on the server. The
  console now says what state a case is in, but the API does not refuse.
- There is no password reset, in the console, the API or
  `scripts/bootstrap.py`. An administrator can re-enrol an authenticator
  or clear a lockout; a forgotten password has no way back.
- Rejecting a sample asks for no step-up, although it moves evidence into
  a store it cannot leave without two people.
- Console strings in `app.js` and `index.html` still carry dashes that the
  documents no longer do.
- On a case classified above the invoker's clearance, an exhibit, capture
  screenshot or entity write under break-glass is counted twice: once by
  the case gate and once by the item's own. Stopping it needs a
  `count_use` passthrough on `deps.authorize_object`.
- A capture's classification is not copied into the proposals it yields,
  so they accept at AMBER whatever the capture was (the Triage row above,
  confirmed again by the second review).
- `GET /ach` now leaves out cells above the reader, but the ACH pane does
  not say that anything was left out.
- `url_norm` drops a URL's fragment, so fragment-keyed links (`mega.nz/#!`)
  collapse into one selector. That is an ontology identity rule, not a
  search defect.
- A stale sign-in on any other step-up route still reads "missing
  permission" rather than asking to re-authenticate; the report release
  is the one route taught the difference.
- The HTTP API still grades a claim for the caller when the body leaves
  it out (`AssertionBody` defaults to DIRECT_OBSERVATION, F6, LOW). The
  console forms no longer pre-grade anything, but invariant 1 at the API
  wants the grading to be required.
- Nothing writes `core.node.first_seen`, so the entity list's First seen
  column can never fill through the product. Either give entity creation
  a first seen or derive it from the earliest observation.
- The seeded retention rules' rationales cite design documents on screen
  (migration 0032 data); a data migration would reword them.
- `nightmarket.im`, a real country-code domain, appears in the other demo
  seeders and in tests. The README estate uses `.example` hosts throughout.

---

## Open questions for the operator

- **Ingest key holders.** Internal scripts only, or external partners? It
  changes the support and abuse model (docs/16 D6).
- **Expected ingest volume.** Above roughly 1M records a day the bucket needs
  a different storage tier.
- **Which sandbox vendors count as private** for detonation exposure. Several
  "private" tiers still share hashes with partners.
- **Who is the security officer?** Break-glass refuses to grant while no
  active account holds `SECURITY_OFFICER`, and the readiness register blocks
  on it.
- **Retention periods.** Six placeholder rules ship in migration 0032, and
  purge warns loudly on every one nobody has confirmed.
- **How large is an exhibit?** `NOCTORNAL_MAX_EVIDENCE_BYTES` must be declared
  before a production boot, because every accepted byte is locked under
  COMPLIANCE for the whole retention period (docs/08).
- **Do compartments ever retire?** Nothing can delete or rename a registered
  key while a row carries it.

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
- **Do not run the suite while another agent runs theirs.** The end-to-end
  cleanups delete by email pattern, so concurrent runs delete each other's
  fixtures and the failures look real.
- **uvicorn runs without `--reload`.** A new route 404s until restart.
- **TOTP codes are single-use.** Two sign-ins inside one 30-second step fail
  on the replay guard, not on the thing under test. Where the host clock is
  unsynchronised, `bootstrap.py session --email <you>` mints one directly.

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
