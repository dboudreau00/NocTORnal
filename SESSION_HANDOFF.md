# Session handoff — 2026-07-26

Written so a fresh session can resume without re-deriving anything.
Supersedes the 2026-07-25 Phase 7 handoff; that session's content lives in
`docs/17` and the commit log.

> **Read order:** this file → **`docs/18-legal-review-pack.md`** (the
> register as a *decision document* — hand this to a reviewer) →
> `docs/17-flagged-for-review.md` (engineering judgement, and the rows
> already recorded that should not be trusted) → `ROADMAP-REMAINING.md` →
> `CLAUDE.md` (the twelve invariants) → `docs/00-decisions.md`.

---

## 1. What this is

**NocTORnal** is a HUMINT / social-network-analysis platform for cybercrime
investigation: analysts build a graph of criminal actors, personas, groups
and the trust between them, every element traceable to graded evidence with
a chain of custody. Comparable to Maltego, i2 and SL Crimewall, with
UCINET-grade SNA maths. Python 3.13 / FastAPI / Postgres 16, plain-HTML
analyst UI under a strict CSP with no build step.

## 2. Where it is

**~85% complete** on a four-dimension weighted measure (model+tests 45%,
HTTP API 15%, analyst UI 25%, adversarial review 15%).

- **1117 tests, 0 skipped.** Alembic head **0042**. ruff clean.

  ⚠ **The last FULL-suite run I have evidence for was 1108 passing, before
  the Phase 8 fixes.** After them I ran `test_samples_pg.py` and
  `test_samples_hardening_pg.py` together — 49 passed — and lint over
  `apps/`. **Run the full suite before trusting the number above.** The
  contract change (`download()` now requires a clearance) touched seven
  existing call sites and they are fixed, but I did not re-run everything.
- Every phase has a service, tests and an HTTP API.
- **Five analyst panes** beyond the original set: **Comms**, **Feeds**
  (ingest queue / dead letters / sources / keys), **ACH**, **Lifecycle**
  (retention / destroyed / break-glass) — alongside Graph, Entities,
  Evidence, Triage, Inbox, Analysis and Search.
- Nothing pushed — no remote is configured.

## 3. What changed in the 2026-07-26 session

1. **All ten F15 service defects fixed at the service**, not merely
   compensated for at the router. Migrations 0040–0042.
2. **Raw-before-parse became real.** `accept()` had been acknowledging
   batches and dropping the bytes; `rawstore.py` stores them in their own
   bucket with **no object lock** (an exhibit is locked so not even root
   can delete it; a partner's unvetted submission on a 90-day clock must
   stay deletable), and `accept()` now refuses when it has nowhere to put
   them.
3. **Three new panes**, a logo and favicon, `#case=…&tab=…` deep links,
   and `scripts/screenshot_ui.py`.
4. **The ingest retention clock is now read.** It had ticked since
   migration 0033 with nothing sweeping it — so the 90-day default chosen
   *because* unassessed victim data deserves the shortest rule was
   delivering the longest possible one.
5. **A fourth adversarial pass**: 25 findings, 16 survived refutation, 14
   fixed. Recorded as **docs/17 F17**. Most were in the *fixes* from
   earlier the same day.
6. **`docs/18-legal-review-pack.md`** written: every legal question with
   its option set, the consequence of each, the current default and a row
   to write the answer in — plus a retrospective section.

---

## 4. WHERE I STOPPED — resume here

**The Phase 5/8 adversarial pass ran and its results are only half
actioned.** That is the single most important thing in this file.

### 4.1 What the pass found

27 findings survived refutation, **9 of them CRITICAL**, all in Phase 8 —
which had never been reviewed. Full list in the workflow output at
`%TEMP%\claude\…\877b50ed-…\tasks\whjkfqq7q.output` (JSON; the extractor
`scratchpad/findings58.py` renders it readably). The nine criticals have
two distinct root causes, and **both are now FIXED and committed**:

1. **`download()` applied no label check of any kind** — not the sample's
   classification, not its compartments, not its case's. `queue()` filters
   and `detail()` 404s, so the same caller was told the sample did not
   exist and was handed its bytes one request later, on the one path in
   the system that puts working malware on somebody's disk. Fixed: the
   labels are applied IN the query, the case's are composed with the
   sample's (`greatest(...)` / `||`), and a caller who may not read it
   gets "no such sample" rather than a refusal.

2. **The "encrypted archive" was a plain ZIP.** Python's `zipfile` cannot
   write encrypted entries — `setpassword()` is decrypt-only — so
   `ARCHIVE_PASSWORD` was defined, exported in `__all__` and referenced by
   nothing. The entry carried flag bits `0x0000` and opened with no
   prompt in Explorer, 7-Zip, a mail gateway or an EDR agent, **while the
   archive comment and the `X-Sample-Archive-Password` header both told
   the analyst a password protected it.** Fixed: real traditional
   ZipCrypto, written by hand because there is no stdlib API, verified by
   round-tripping through Python's own decryptor (refuses with no
   password, refuses with a wrong one, `testzip()` clean).

### 4.2 What is NOT done — start here tomorrow

**The other 18 surviving findings are unactioned and unrecorded.** They
are NOT yet in `docs/17`; the only place they exist is the task output
above. Read it first. The ones I had already read and judged real:

| | |
|---|---|
| HIGH, egress | **Report release launders the case's own classification.** A RED case emits a document marked TLP:CLEAR — the graph body is correctly empty, but `report.case` copies code, title, summary and legal_basis unfiltered, so `marking` falls to CLEAR and the gate is fed the laundered value. |
| HIGH, egress | **`can_egress` is called with the exhibit's OWN compartments, and nothing ever sets them** — `core.evidence.compartments` defaults `'{}'` and no trigger propagates the case's. `DENY_COMPARTMENTED` can therefore never fire for evidence. |
| HIGH, drift | **`reports.check_egress` drops the compartments argument entirely**, so the two call sites of the single shared gate disagree about one of its three arguments. |
| HIGH, drift | **`reject()` destroys sample bytes and the data key while ignoring `legal_hold`** — one non-step-up call irreversibly destroys material under a court hold. `lab.sample.legal_hold` exists and is read by nothing. |
| HIGH, notify | **The notification centre never checks case assignment.** A revoked or expired analyst keeps reading case content from `/notifications` indefinitely; every other "which cases can this caller see" query in the repo carries the `expires_at` predicate. |
| HIGH, notify | **`approval_requested` notifies users whose assignment has EXPIRED** — a fresh WRITE of case material to someone the gate would 404. |
| HIGH, notify | **Every notification is labelled with its CASE's classification, never the element's.** `effective_labels_for_notification` exists, is exported, has a test, and has **zero production call sites**. |
| HIGH, drift | **The outbox drain never re-checks the recipient's CURRENT clearance**, so a revoked analyst still gets the case summary by email — the one path that actually leaves the boundary. |
| HIGH, lifecycle | **`submit()` writes hostile bytes to the object store before the row exists.** Any DB failure after that leaves an unrecorded, unattributable copy of live malware in a WORM bucket. An unvalidated `classification` Form string reaches a `core.tlp` column and raises. |

**Suggested order:** the notification/egress cluster first (four of them
are the same missing `expires_at` / current-clearance predicate), then
`reject()` and legal hold, then `submit()`'s write ordering.

### 4.3 Then: the rest of the review discipline

Every pass on this project has found a real defect — five for five now,
four times a critical one, every time under a fully green suite. Give
each reviewer a distinct hostile lens and run a refutation round; about a
third of a first pass does not survive contact with the code. `docs/17`
F15 and F17 show the shape and the depth expected.

### 4.2 Two retrospective items (docs/18 Section D)

Neither scores on the completion measure and both are real:

- **`scripts/redact_dead_letters.py --apply` has not been run.** Rows
  recorded before the redactor still hold their fragments verbatim. They
  are labelled, on a clock and withheld from the API — but they are there.
- **Batches accepted before object storage was wired cannot be
  re-parsed.** The API says so honestly rather than parsing an empty
  payload and marking the batch complete. If real feeds submitted during
  that window, the partner has to resend.

### 4.3 Remaining UI

Merge, reports, and samples. **Samples last and carefully**: invariant 10
says metadata may render and bytes may not, and no sandbox attribute may
combine `allow-scripts` with `allow-same-origin`.

Three things the five panes built so far taught, worth carrying forward:

- **`Promise.all` over endpoints with different permissions is wrong.**
  The first 403 rejects the lot, so a caller holding four of five
  permissions sees an empty pane claiming they hold none. Load each
  section independently.
- **A permission error is not an empty state** — and show the server's
  `detail` first. A hard-coded "you need permission X" tells the *holder*
  of X that they do not hold it, because a stale step-up 403s too.
- **Look at it rendered.** Two defects this session were invisible to the
  suite and obvious on a screenshot in ten seconds.

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
`&case=<uuid>&tab=feeds` to land on a specific pane.

**uvicorn does NOT run with `--reload`.** A new route 404s until restart —
this has cost real debugging time more than once.

### Useful scripts

| | |
|---|---|
| `scripts/seed_feeds_demo.py --case OP-X` | Ingest queue, a folded duplicate, a redacted dead letter, sources |
| `scripts/seed_ach_demo.py --case OP-X` | An ACH matrix where the obvious hypothesis loses — the method working, not a seeding mistake |
| `scripts/screenshot_ui.py --email <you>` | Every pane, headless Chrome, through the deep links |
| `scripts/redact_dead_letters.py` | The outstanding repair. Dry-run by default |

---

## 6. Traps

- **Bash may be unavailable.** Git for Windows was gutted mid-session by
  antivirus reacting to malware a parallel workstream cloned into this
  tree; use PowerShell, and `git` may need `C:\Program Files\Git\cmd` on
  PATH.
- **gpg must be on PATH** or the PGP tests fail rather than skip — that is
  deliberate: the only cryptographic-evidence path in the system should
  break the build if it goes untested. `C:\Program Files\GnuPG\bin`.
- **Do not run the suite while review agents run theirs.** The e2e cleanup
  deletes by email pattern and concurrent runs delete each other's
  fixtures. The failures look real and are not.
- **A test that purges cannot delete its case or its actor.**
  `core.purge_tombstone` has foreign keys to both and an append-only
  trigger — the record of a destruction outlives what it refers to. That
  is correct rather than inconvenient.
- **`NOT VALID` does not exempt UPDATEs**, only rows present at ALTER
  time. This bit `replay()` on pre-0040 dead letters.
- **Append-only records outlive their subject, so a test cannot always
  clean up after itself.** `lab.sample_access`, `core.purge_tombstone` and
  `audit.event` all raise on DELETE, and all three carry foreign keys to
  the thing they describe — so a test that downloads a sample cannot
  delete the sample OR the actor, and a test that purges cannot delete its
  case. That is the design working. Teardown has to check and skip, not
  assume. Three separate suites hit this in one day.
- **`submit()` deduplicates on content**, so a fixture with a fixed
  payload fails on the previous test's row. Make the bytes unique.
- **`for x in gen()` puts the `next()` outside your try blocks.** Twice
  now that has dropped every remaining fragment of a batch with no
  accounting.
- **`array_length('{}', 1)` is NULL, not 0.** Any `>= 1` check on an array
  needs `coalesce` or it silently passes on the empty case.
- **Teardown order follows the foreign keys, not the reading order**, and
  a test that fails part-way never reaches its inline cleanup — put it in
  the fixture.
- **`alembic downgrade base` strands the dev database around 0017** (it
  has data). Use a scratch database and install `vector`, `pg_trgm`,
  `pgcrypto`, `btree_gist`, `citext`, `uuid-ossp` first, or the chain dies
  at 0004 with "type vector does not exist" — which reads as a migration
  bug and is not one.
- **A locale can hide a security defect.** The PGP status-injection flaw
  was live under UTF-8 and inert under this host's cp1252. Where a defence
  depends on how bytes decode, assert on the BYTES.
- **Check the claim, not just the code.** The dead-letter redactor's
  docstring said the verbatim bytes remained in the batch's raw object —
  the whole reason redacting the fragment is safe rather than lossy. It
  was false, and it was found by writing the sentence down and then going
  to look.

---

## 7. The part that is not code

`docs/18` holds **4 blocking legal items, 10 operator determinations, 14
external confirmations and 3 retrospective items.** A 100% build is still
one that must not be operated until the four blockers are settled, and
Phase 8 is the clearest case: it could reach 100% on the completion
measure and still must not be switched on.
