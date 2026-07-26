# Session handoff — 2026-07-26 (second session)

Written so a fresh session can resume without re-deriving anything.
Supersedes the earlier 2026-07-26 handoff.

> **Read order:** this file → **`docs/18-legal-review-pack.md`** (the
> register as a *decision document* — hand this to a reviewer) →
> `docs/17-flagged-for-review.md` (engineering judgement; **F19** is this
> session) → `ROADMAP-REMAINING.md` → `CLAUDE.md` (the twelve invariants)
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

**~92% complete** on a four-dimension weighted measure (model+tests 45%,
HTTP API 15%, analyst UI 25%, adversarial review 15%).

- **1178 tests, 0 skipped.** Alembic head **0044**. ruff clean.

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

Three commits, all on `main`.

1. **`af81c44` — F19, first batch.** The notification and egress clusters,
   plus sample legal-hold and write ordering. Nineteen of twenty-two new
   tests fail on the commit before it.
2. **`683d9df` — the Lab pane**, Phase 8's UI, and two defects only a
   screenshot could find.
3. **`543da59` — F19, second batch.** Samples versus their case's labels
   (migration 0043), the silent integrity alarm, notification delivery
   addresses (migration 0044), the unbuffered size cap, the dedup oracle.

**All 27 findings from the Phase 5/8 adversarial pass are now actioned.**
They are written up in `docs/17` as **F19** — read that rather than the
commit messages.

### The two that matter most, for anyone doing archaeology

- **Phase 8 had 673 green tests and shipped a security control that did
  not exist.** `archive()` produced a plain ZIP; Python's `zipfile` cannot
  write encrypted entries, so `ARCHIVE_PASSWORD` was defined, exported and
  referenced by nothing, while the archive comment and a response header
  both told the analyst a password protected it.
- **`download()` applied no label check of any kind** — on the one path in
  the system that puts working malware on a disk. `detail()` 404'd an
  over-classified sample and `download()` handed the same caller its bytes
  one request later.

---

## 4. WHERE I STOPPED — resume here

Nothing is half-done. The suite is green, the tree is clean, and the next
step is a choice rather than a continuation.

### 4.1 The highest-value next work

| | | |
|---|---|---|
| **1** | **A hostile pass over THIS session's fixes** | The pattern has held twice now: the 2026-07-25 evening pass found that *most of its findings were in the previous pass's fixes*, and this session repeated it — a filename defence written that morning was defeated by the exact attack it was written for, and only a screenshot showed it. This session changed three service signatures, added two migrations and rewrote the notification read path. |
| **2** | **Phase 6's review** | The last phase with only a partial pass. |
| **3** | **Per-phase feature gaps** | Adapters (Phase 4), WebAuthn and timeline replay (6), Jira and a worker (5), fuzzy hashing and YARA (8). `ROADMAP-REMAINING.md` §4. |
| **4** | **The two retrospective items** | `scripts/redact_dead_letters.py --apply` has still not been run, and batches accepted before object storage was wired cannot be re-parsed. docs/18 Section D. Neither scores on the completion measure; both are real. |

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
