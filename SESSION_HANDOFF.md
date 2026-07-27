# Session handoff — 2026-07-26 (third session)

Written so a fresh session can resume without re-deriving anything.
Supersedes both earlier 2026-07-26 handoffs.

---

## 0. What the THIRD session did (2026-07-26, evening)

Branch **`deception-and-release-hardening`**, four commits on top of
`d4595ff`. Nothing pushed — there is still no remote.

**(a) The deception subsystem** — `docs/19`, migrations 0046–0050,
`deception.py`, its router, its pane, 52 tests. Phishing captures, BEC
email forensics, vishing call records. Three rules carry it: a captured
page is attacker-authored code (invariant 10 generalised), the displayed
identifier is the spoofed one (invariant 9 generalised), and the Received
chain is trustworthy inwards only. See ARCHITECTURE's new section.

**(b) `FinalCodeReviewFindings.md` fully remediated.** All 18 CONFIRMED
code findings, the 1 PLAUSIBLE, and all 21 release findings. The two
REFUTED were correctly refuted. Every entry in that file now carries a
`✅ FIXED` line naming what changed. Two migrations came out of it: 0051
re-keys Telegram selectors after the decode fix, 0052 adds the two missing
TRUNCATE guards.

  - **CR1 was a real confidentiality breach**: `target_tlp` travelled from
    the query string into `GraphService(clearance=...)` unclamped, so an
    AMBER analyst could request a RED report and get RED nodes and exhibit
    hashes. Both call sites already computed `user_ceiling()` and used only
    index `[1]`.
  - **CR3 closed determination D8**, which `docs/16` carried as knowingly
    unfixed. The Telegram Bot-API encoding is arithmetic, not a text
    prefix; the old string-strip was correct only for a ten-digit channel
    id, which is exactly what its one test used.

**(c) Release packaging.** AGPL-3.0-or-later (forced — `igraph` is
GPL-2.0-or-later, `leidenalg` GPL-3.0-or-later, both imported by
`analytics.py`, so no permissive licence was available; see `NOTICE.md`).
Rewritten README with 16 screenshots and three mermaid diagrams,
`SECURITY.md`, `CONTRIBUTING.md`, `scripts/package_release.ps1` (git
archive, verified), OpenFGA and NATS removed from compose.

**Screenshots are a TLP:CLEAR synthetic case** (`OP-SHOWCASE-26`, seeded
by `bootstrap.py demo-network` + `scripts/seed_deception_demo.py`).
`.gitignore`'s blanket `*.png` rule is negated ONLY for `docs/images/`;
`screenshots/` and `shots/` stay ignored. **Check the TLP badge reads
CLEAR before adding any image there.**

### Two things worth carrying forward

1. **A test can encode the wrong mental model.** The Received-chain
   boundary test was written asserting that the attacker's originating IP
   should be EXCLUDED. It should not: our own relay wrote that line, so it
   is our observation and the single most valuable identifier in the
   message. The code was right and the test was wrong.

2. **The ninth instance of this project's recurring defect shape.** The
   R10 fix added comments *inside* `minio-init`'s `entrypoint: >` — a YAML
   **folded** scalar — so the `#` joined onto one shell line and commented
   out the very bucket creation it described. `docker compose config`
   caught it; reading the diff did not.

---

> **Read order:** this file → **`docs/18-legal-review-pack.md`** (the
> register as a *decision document* — hand this to a reviewer) →
> `docs/17-flagged-for-review.md` (engineering judgement; **F19** is this
> session) → `ROADMAP-REMAINING.md` → `CONVENTIONS.md` (the twelve invariants)
> → `docs/00-decisions.md`.

---

## 1. What this is

**NocTORnal** is a HUMINT / social-network-analysis platform for cybercrime
investigation: analysts build a graph of criminal actors, personas, groups
and the trust between them, every element traceable to graded evidence with
a chain of custody. Comparable to Maltego, i2 and SL Crimewall, with
UCINET-grade SNA maths. Python 3.13 / FastAPI / Postgres 16, plain-HTML
analyst UI under a strict CSP with no build step.

## 2. Where it is

**~97% complete** on a four-dimension weighted measure (model+tests 45%,
HTTP API 15%, analyst UI 25%, adversarial review 15%).

- **1252 tests, 12 skipped.** Alembic head **0052**. ruff clean.
  (Without `DATABASE_URL` you see ~700 skips — half the suite is
  deliberately database-gated. That is a correct result.)
- **`release/` is the packaged Alpha release** — README leading with the
  legal status, an analyst MANUAL, INSTALL, and one-shot installers for
  Windows and Linux/macOS. `scripts/package_release.ps1` exports the whole
  tree to a standalone folder; `release/` is the source of truth.

  ⚠ **The count spans TWO roots.** `apps/api/tests` (1079) and
  `packages/ontology` (99). Run both:

  ```
  .venv\Scripts\python -m pytest apps/api/tests packages/ontology -q
  ```

  A previous handoff quoted one figure without saying so and the next
  session spent time working out why it did not reconcile.
- **Every phase has a service, tests, an HTTP API, an analyst pane and an
  adversarial review.** Phase 6's review is the only partial one.
- Nothing pushed — no remote is configured.

## 3. What changed this session

Seven commits, all on `main`. `docs/17` **F19** and **F20** are the record
— read those rather than the commit messages.

| | |
|---|---|
| `af81c44` | **F19, first batch.** Notification and egress clusters, sample legal hold, write ordering. Nineteen of twenty-two new tests fail on the commit before it. |
| `683d9df` | **The Lab pane** — Phase 8's UI — and two defects only a screenshot could find. |
| `543da59` | **F19, second batch.** Samples versus their case's labels (migration 0043), the silent integrity alarm, delivery addresses (0044), the unbuffered size cap, the dedup oracle. |
| `f390b9c` | Docs: F19 written down, roadmap to ~92%. |
| `8291e57` | **Three defects in this session's OWN fixes.** |
| `26f4165` | UI: a request indicator for every fetch, and a `?` keyboard sheet. |
| `1d648bc` | **F20: the untested hypothesis was winning the ACH matrix.** |
| `06ad0d8` | Live change push (Phase 2's last gap) and the detonation/VM panel. |
| `fd5f01b` | The Alpha release: installers, manual, legal status first. |
| `1cca5d9` | `.gitattributes`: shell scripts keep LF, or `install.sh` is broken on the Linux box it exists to serve. |
| `d429ed9` | **live: one listener per process, not two connections per client.** |

**All 27 findings from the Phase 5/8 pass are actioned.** So is a hostile
pass over the fixes themselves, and one over Phase 6's ACH.

### The four that matter most, for anyone doing archaeology

- **Phase 8 had 673 green tests and shipped a security control that did
  not exist.** `archive()` produced a plain ZIP; Python's `zipfile` cannot
  write encrypted entries, so `ARCHIVE_PASSWORD` was defined, exported and
  referenced by nothing, while the archive comment and a response header
  both told the analyst a password protected it.
- **`download()` applied no label check of any kind** — on the one path in
  the system that puts working malware on a disk. `detail()` 404'd an
  over-classified sample and `download()` handed the same caller its bytes
  one request later.
- **The ACH matrix crowned the hypothesis nobody had examined.** Zero
  inconsistency is the lowest score the scale can produce, so an untested
  hypothesis sorted first — in the tool built to correct confirmation
  bias, in exactly the situation docs/13 cites as the reason to build it.
  A test had been asserting that behaviour, green, since Phase 6.
- **Closing a hole by refusing everybody is its own defect.** My own report
  fix hardcoded the builder's compartments to empty. It stopped the leak,
  and it also meant a cleared analyst could not name their own case and
  `DENY_COMPARTMENTED` remained unreachable — the exact defect the same
  commit had just repaired elsewhere.
- **The live socket worked with one analyst and would have failed with
  ten.** Two Postgres connections per client, both held; Postgres ships
  with `max_connections = 100`, so twenty-five people with two tabs each
  would have taken the whole API down — a total outage caused by leaving
  tabs open. Now one listener per process, verified at 20 concurrent
  sockets. **Both of that fix's own bugs were found by measuring
  `pg_stat_activity`, not by reading the code**: `asyncio.to_thread`
  cannot be cancelled, so the cleanup ran against a connection another
  thread still held and was silently suppressed; and a disconnect was not
  noticed until the next send, 25 seconds later.

---

## 4. WHERE I STOPPED — resume here

Nothing is half-done. The suite is green, the tree is clean, and the next
step is a choice rather than a continuation.

### 4.1 The highest-value next work

| | | |
|---|---|---|
| **1** | **Finish Phase 6's review** | ACH has now had one and it produced F20. **`merges.py`, `retention.py`, `approvals.py` and `break_glass.py` have not.** I read `approvals.py` and `retention.py`'s purge path closely enough to confirm two specific claims — `consume()` is a genuine atomic compare-and-set, and `purge_out_of_schedule` checks legal hold on both exhibit and case *before* burning the approval — but that is spot-checking, not a pass. |
| **2** | **Another pass over this session's fixes** | The pattern has now held three times: most of a pass's findings land in the previous pass's repairs. One pass has been run over this session's work (`8291e57`, three defects) and it was not exhaustive. Migrations 0043/0044, the rewritten notification read path and the new pane are all one-pass-old. |
| **3** | **Per-phase feature gaps** | Adapters (Phase 4), WebAuthn and timeline replay (6), Jira and a worker (5), fuzzy hashing and YARA (8). `ROADMAP-REMAINING.md` §4. |
| **4** | **The remaining retrospective items** | The dead-letter repair was **checked on 2026-07-26: this database has nothing to fix**, all three rows are already redacted. That closes it here and not on any deployment that ran pre-0040 code. Still open: batches accepted before object storage was wired cannot be re-parsed, and whether the original exposure is reportable — which "nothing left on this machine" does not answer. docs/18 Section D. |

### 4.2 If you touch the UI

`scripts/screenshot_ui.py --email <you>` renders every pane through the
deep links. **Use it.** Five defects in this work were invisible to the
suite and obvious on screen in ten seconds, including two this session.

`scripts/seed_lab_demo.py --case OP-X` fills the Lab queue with a
realistic spread — a packed PE near 8.0, a plain one near 5.5, an ELF, an
OOXML, a script, one with a right-to-left override in its filename, one
rejected. **Nothing it writes is malware:** every payload is a synthetic
buffer with a real magic and a chosen entropy profile.

`apps/api/tests/test_ui_invariants.py` checks the properties that live in
the assets rather than in the API — no markup assignment anywhere, no
iframe, nothing in the Lab pane that can fetch or decode, the bidi
substitution table, and that no animation can leave content invisible.

---

## 5. Running it

```
powershell -ExecutionPolicy Bypass -File "scripts\launch.ps1"
```

Add `-SkipDocker` when the stack is already up. UI at
<http://127.0.0.1:8000/ui/>.

**TOTP cannot work on this host** — its clock is unsynchronised and sits in
2026, and TOTP is a function of absolute time. Do not debug the secret or
the authenticator. Sign in with:

```
.venv\Scripts\python scripts\bootstrap.py session --email <you>
```

That prints a URL carrying the token in the fragment. Append
`&case=<uuid>&tab=samples` to land on a specific pane.

**uvicorn does NOT run with `--reload`.** A new route 404s until restart —
this has cost real debugging time more than once.

**Sample ingest refuses until a policy is declared.** For development:

```
$env:NOCTORNAL_PROHIBITED_CONTENT_POLICY = "DEV-POLICY-0"
$env:NOCTORNAL_DESIGNATED_PERSON = "dev operator"
```

That is a *declaration the software records*, not one it can verify. See
docs/18 L1.

### Useful scripts

| | |
|---|---|
| `scripts/seed_feeds_demo.py --case OP-X` | Ingest queue, a folded duplicate, a redacted dead letter, sources |
| `scripts/seed_ach_demo.py --case OP-X` | An ACH matrix where the obvious hypothesis loses — the method working, not a seeding mistake |
| `scripts/seed_lab_demo.py --case OP-X` | The Lab queue. Synthetic payloads with real magics |
| `scripts/screenshot_ui.py --email <you>` | Every pane, headless Chrome, through the deep links |
| `scripts/redact_dead_letters.py` | The outstanding repair. Dry-run by default |

---

## 6. Traps

- **The test count is TWO roots.** `apps/api/tests` and
  `packages/ontology`. See §2.
- **`alembic` must run from the repo root.** `alembic.ini` is there, not in
  `db/`. From `db/` it fails with "No 'script_location' key found in
  configuration", which reads as a broken install and is not.
- **Append-only records outlive their subject, so a test cannot always
  clean up after itself.** `lab.sample_access`, `core.evidence_custody`,
  `core.purge_tombstone` and `audit.event` all raise on DELETE **and**
  carry foreign keys to what they describe — so a test that ingests
  evidence can never delete that evidence, its case, or the user named on
  the custody row. That is the design working. Teardown has to check and
  skip. Four suites have now learned it the same way.
- **`submit()` deduplicates on content**, so a fixture with a fixed
  payload fails on the previous test's row. Make the bytes unique.
- **`dispatch_due` drains the WHOLE outbox**, so a test asserting on a
  global "sent" list passes or fails on whatever another suite left
  behind. Tag your notification and assert on yours.
- **Bash may be unavailable.** Git for Windows was gutted in an earlier
  session by antivirus reacting to malware a parallel workstream cloned
  into this tree; use PowerShell, and `git` may need
  `C:\Program Files\Git\cmd` on PATH.
- **gpg must be on PATH** or the PGP tests fail rather than skip — that is
  deliberate: the only cryptographic-evidence path in the system should
  break the build if it goes untested. `C:\Program Files\GnuPG\bin`.
- **Do not run the suite while review agents run theirs.** The e2e cleanup
  deletes by email pattern and concurrent runs delete each other's
  fixtures. The failures look real and are not.
- **`NOT VALID` does not exempt UPDATEs**, only rows present at ALTER
  time.
- **`array_length('{}', 1)` is NULL, not 0.** Any `>= 1` check on an array
  needs `coalesce`.
- **`for x in gen()` puts the `next()` outside your try blocks.** Twice
  now that has dropped every remaining fragment of a batch with no
  accounting.
- **`alembic downgrade base` strands the dev database around 0017.** Use a
  scratch database and install `vector`, `pg_trgm`, `pgcrypto`,
  `btree_gist`, `citext`, `uuid-ossp` first, or the chain dies at 0004
  with "type vector does not exist" — which reads as a migration bug and
  is not one.
- **A locale can hide a security defect.** The PGP status-injection flaw
  was live under UTF-8 and inert under this host's cp1252. Where a defence
  depends on how bytes decode, assert on the BYTES.
- **A character class of literal invisible characters will be mangled.**
  It happened while the bidi defence was being written. Use `\uXXXX`.
- **Check the claim, not just the code.** Two defences in this codebase
  asserted the opposite of the truth in their own docstrings — the
  dead-letter redactor's, and `archive()`'s. Both were found by writing
  the sentence down and then going to look.
- **A green test can be asserting the defect.** Three times now.
  `test_a_report_carries_the_alternatives_that_were_ruled_out` scored one
  hypothesis, left the other untouched and asserted that the untouched one
  won — green since Phase 6, encoding the bug as the expectation. A test
  written from the implementation inherits the implementation's mistakes.
- **uvicorn serves STATIC files from disk and Python from memory.** An
  `app.js` or `app.css` edit is live on reload; a service change is not,
  and the running API will happily serve a UI that reads a field the old
  code does not send. Restart after touching Python, or you are testing
  two versions at once.
- **`asyncio.to_thread` cannot be cancelled.** Cancelling the task raises
  at the await point immediately and leaves the worker thread running with
  whatever it was holding. Any cleanup in `finally` then runs against a
  resource another thread is still using — and if it is wrapped in
  `contextlib.suppress`, it fails silently. Use a flag the loop checks.
- **A shell script committed from Windows will be checked out with CRLF
  unless `.gitattributes` says otherwise**, and `#!/usr/bin/env bash\r` is
  not a shebang. The error names neither the file nor line endings.
- **Do not run `release/install.sh` under Git Bash.** It now refuses, but
  the reason is worth knowing: a Windows virtualenv puts its interpreter
  in `Scripts/` rather than `bin/`, so the "does a venv exist?" check said
  no and it recreated one over a working environment.

---

## 7. The part that is not code

`docs/18` holds **4 blocking legal items, 10 operator determinations, 14
external confirmations and 3 retrospective items.** A 92% build is still
one that must not be operated until the four blockers are settled, and
Phase 8 is the clearest case: it is now at 80% with a reviewed model, a
gated API and a working UI, **and it must not be switched on.**

The four blockers, compressed:

| | What | Why it blocks |
|---|---|---|
| **L1** | Prohibited-content policy for samples | The build refuses ingest until a policy reference and a designated person are declared — but that is a declaration it *records*, not one it can verify. **Partly moved this session:** `reject()` now refuses to destroy material under a legal hold and puts the preservation-versus-destruction conflict in front of a person, rather than resolving it silently in favour of destruction. |
| **L2** | Stealer-log lawful basis, victim notification, real retention | Holding data about thousands of uninvolved people. 90 days is a placeholder. |
| **L3** | Persona operation authority | The software will drive an account into a forum. Whether you may is not a software question. |
| **L4** | Interception law and consent | Message capture. `provenance_class` records *which* kind; the authority is external. |

One more for the register, unrelated to any engineering work: **a parallel
session cloned live malware samples into this OneDrive-synced tree**, and
the antivirus quarantined mid-clone. Whether material synced to cloud
storage before quarantine is a question for counsel, not for this file.
It is recorded as docs/18 Section D3.
