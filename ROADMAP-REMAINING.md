# What is left on the roadmap

Regenerated 2026-07-26. `docs/09-roadmap.md` is the plan; this is the
honest delta between that plan and the build.

> **Corrected 2026-08-10 by a read-only audit of the CODE behind each row.
> Six of this file's own claims were wrong**, and every one of them was
> wrong in the direction that makes the build look better understood than
> it was:
>
> 1. The metric-history endpoint was named `metrics/history`. It is
>    `GET /analytics/history/{node_id}`, so the string this file handed
>    the reader finds nothing and reads as "never built".
> 2. Phase 6's gap listed **WebAuthn** (a deliberate absence stated in
>    four documents — SECURITY.md says reporting it is not a finding) and
>    **timeline replay** (built, and part of Phase 2). Both struck.
> 3. Phase 6's "**The UI is complete**" was false: approvals have no
>    analyst surface, so Merge is unreachable from the browser under dual
>    control.
> 4. The 0017 downgrade names one foreign key; there are five, plus a
>    second instance in 0031. Now closed as deliberate, with
>    `CONVENTIONS.md` corrected rather than the migration.
> 5. The 67 forks and "`seq` order is not chain order" are recorded as two
>    observations. They are **one defect** with one root cause.
> 6. Two entries filed under "unverified leads" were both real, and one
>    was worse than the lead said.
>
> The pattern is the one this file already names about the code, turned on
> the file itself: *a claim nobody checked*. It now has one — the document
> links are asserted by `test_doc_invariants.py`, after `docs/17` (cited
> seventeen times, including by SECURITY.md as the first thing an external
> researcher should read) spent three days absent from the tree with a
> fully green suite.

**State (2026-08-10):** branch `deception-and-release-hardening`, Alembic
head `0055`, **1794 passing, 0 failing, 0 skipped** on a live stack —
Postgres, Redis, MinIO and Mailpit up, both pytest roots, 4m36s. The rise
from 1444 is ~350 NEW tests, not new code under test: the element-id
invariant became derived (22 hand-listed ids → 297), plus
`test_doc_invariants.py` and the contract tests carried by this session's
fixes. **This is the first run in this file's history that was executed
rather than inherited from a handoff** — every earlier figure here was
copied forward. The flaky `test_ratelimit_redis` PASSED on this run; it is
intermittent, so that is not evidence it is fixed, and it stays on the
list below.

**Superseded (2026-08-07):** 1444 passing, 0 failing, 0 skipped (run BOTH
`apps/api/tests` and `packages/ontology` — earlier handoffs quoted a single
figure and the next session spent time working out why it did not
reconcile), ruff clean, source hygiene clean across 273 files. The full
migration chain round-trips `head → base → head` on a scratch database
with the extensions installed, which is what CI checks.

> **`test_ratelimit_redis::test_redis_and_python_agree_request_for_request`
> is TIMING-SENSITIVE and fails intermittently — it passed on the run
> above and failed on the two before it, diverging at a different
> iteration each time. Not fixed on purpose.** It compares a
> Redis-backed GCRA against an in-process one over thirty iterations, so
> the Redis side pays thirty network round trips the local side does not;
> with a 0.05s emission that drift crosses a boundary at iteration 23. The
> algorithms agree — every single-backend test passes. Widening the
> tolerance would turn it green while destroying the only interesting
> thing it checks. The fix is an injected clock so neither backend pays for
> the transport; the mechanism is written up in the test's own docstring.

> **This header said `0045` / 1206 tests until 2026-07-26, when it was
> seven migrations and 78 tests behind.** Everything in this file predates
> the deception subsystem (0046–0050), the Telegram re-key (0051), the
> TRUNCATE guards (0052) and an 18-finding code review. Treat any
> unqualified claim below as *as-of the 26th* unless it carries a later
> date — and see "Verified gaps the scoreboard misses" for what a
> code-level audit found that the percentages do not show.

**`release/` is the packaged Alpha release** — a README leading with the
legal status, an analyst manual, install instructions and one-shot
installers for Windows and Linux/macOS. `scripts/package_release.ps1`
exports the WHOLE tree to a standalone folder via `git archive`;
`release/` is the source of truth and the copy is disposable.

> **EVERY PHASE HAS NOW HAD AN ADVERSARIAL PASS.** Phases 5 and 8 were the
> last two, reviewed 2026-07-26: **27 findings survived refutation, nine
> CRITICAL, all now fixed with regressions** (docs/17 F19). Phase 8 had
> 673 green tests and shipped a security control that did not exist — its
> "encrypted archive" was a plain ZIP — and its download endpoint applied
> no label check of any kind.
>
> Six passes, six times a real defect, four times a critical one, every
> time under a fully green suite. Treat an unreviewed change as unknown
> rather than fine.

> **The most important files in the repo are
> [`docs/16-legal-and-external.md`](docs/16-legal-and-external.md) and
> [`docs/18-legal-review-pack.md`](docs/18-legal-review-pack.md).** Every
> phase is built. Five of them cannot lawfully be operated until somebody
> outside this codebase makes a decision. docs/16 is that list organised
> the way the code is; **docs/18 is the same list organised the way a
> review is** — every question, its option set, the consequence of each,
> the current default, and a row to write the answer in. Hand somebody
> docs/18.

---

## Scoreboard

### How these numbers are calculated

Earlier versions of this file scored a phase on whether its **service code
and tests** existed, which is why several read 70–90% while an analyst
could not reach the feature at all. A phase is only finished when somebody
can *use* it and *trust* it, so completion is now weighted across four
dimensions:

| Dimension | Weight | Done means |
|---|---|---|
| **Model, service and tests** | 45% | Schema, service logic, migrations that round-trip, tests named for the invariants they protect |
| **HTTP API** | 15% | Routed, gated by the five-part access check, rate-limited |
| **Analyst UI** | 25% | Reachable and usable in the browser, not only by `curl` |
| **Adversarial review** | 15% | A hostile pass with findings reproduced before being acted on |

**The numbers below are lower than the previous version's. Nothing
regressed — the measure got honest.**

### Per phase

| Phase | Complete | Model+tests | API | UI | Reviewed | The gap |
|---|---|---|---|---|---|---|
| 0 — Foundation | **100%** | ✅ | ✅ | ✅ | ✅ | Nothing. No typecheck, deliberately (decision 42). |
| 1 — Graph core | **100%** | ✅ | ✅ | ✅ | ✅ | Nothing. |
| 2 — Sociogram | **100%** | ✅ | ✅ | ✅ | ✅ | Nothing. **Live push landed 2026-07-26** — Postgres LISTEN/NOTIFY, one listener per process, the socket carrying no case content. |
| 3 — Analytics | **85%** | ◐ | ✅ | ◐ | ✅ | CONCOR; charting metric history. Bipartite→one-mode landed for conversations only — actor×forum and actor×wallet still use two-mode presets, and `_mode_warning` still says so. |
| 4 — Collection | **75%** | ◐ | ✅ | ✅ | ✅ | XenForo/MyBB/Telegram adapters, embeddings, a scheduler process. UI landed 2026-07-25 (Feeds → Sources). All ten F15 service defects fixed at the service, with regressions. |
| 5 — Notification | **85%** | ✅ | ✅ | ◐ | ✅ | Jira, the integration admin surface, escalation of an unacknowledged priority-1, a worker. **Reviewed 2026-07-26** (F19): the centre never checked case assignment, the outbox drain checked neither assignment nor current clearance, and the label composer had zero call sites. All fixed. |
| 6 — Tradecraft | **88%** | ◐ | ✅ | ◐ | ◐ | ~~WebAuthn, timeline replay,~~ the assumptions register. **Corrected 2026-08-10 — two of the three named gaps were bookkeeping errors and the UI claim was false.** WebAuthn is a DELIBERATE absence stated in four documents, and SECURITY.md says reporting it is not a finding; timeline replay is BUILT, and belongs to Phase 2. The assumptions register is the only genuine remaining feature. **"The UI is complete" was wrong**: approvals have no analyst surface at all — the one `approvals` reference in `app.js` is a button that switches tab — so `runMerge()` cannot obtain the `approval_request_id` its own 409 demands, and under dual control Merge is unreachable from the browser. ACH stance and the dual-control policy toggle have no surface either. What remains is the assumptions register, those three surfaces, and a hostile review of the phase as a whole. |
| 7 — Comms | **95%** | ✅ | ✅ | ✅ | ✅ | **Effectively done.** The Comms pane covers the normalise preview, the contact-block parser, binding, correlation, PGP verification with its three outcome classes, the unverified queue and co-participation. ~~What is left is the Telegram id-collision model change (F1 / docs/16 D8)~~ — **D8 was CLOSED 2026-07-26** by migration 0051: `telegram_id_norm` namespaces every id `u:`/`c:`/`g:` and accepts an explicit prefix from a collector that knows the type. What is left is optional: detached signatures, and a keyserver-free way to obtain a vendor key. |
| 8 — Samples | **80%** | ✅ | ✅ | ✅ | ✅ | Fuzzy hashing (imphash/ssdeep/TLSH), YARA, prohibited-content screening, sandbox integration. Each absence is recorded on the sample row as a gap with a reason. **Reviewed 2026-07-26** — nine criticals, all fixed — and the Lab pane landed the same day. **Still the one phase where 100% here would mean "do not switch on": see L1.** |
| 9 — Ingest | **90%** | ✅ | ✅ | ✅ | ✅ | The outbound credential vault with per-provider quota. Raw object storage landed 2026-07-25 (`rawstore.py`), so raw-before-parse is real rather than aspirational and re-parse works. Triage queue, dead letters and key admin all reached the UI. |

### Overall: **~95%** (was ~84% at the start of 2026-07-26)

Unweighted mean across the ten phases. The +11 came from three things:

- **Phase 8 from 45% to 80%.** It gained the two dimensions it had none
  of: a hostile review (nine criticals) and a UI, plus the detonation/VM
  panel. The largest single move any phase has made.
- **Phase 5 from 70% to 85%**, entirely from its first review.
- **Phase 2 to 100%** — live push, its last named gap.

Three things the number still hides:

1. **UI is no longer the gap at all.** Every phase has a pane, the console
   updates live, and there is a keyboard map. ~~What is left on that axis is
   metric-history charting.~~ **Metric-history charting landed 2026-08-10.**
   What is left on that axis is Phase 6: approvals have no analyst surface
   at all, which makes Merge unreachable from the browser whenever dual
   control is on — see the corrected Phase 6 row.
2. **Completion is not lawfulness.** A phase at 100% here may still be
   unlawful to operate. Phase 8 is now at 80% and **must not be switched
   on** until L1 is settled — see the register below. That is not a
   caveat on the number; it is the point.
3. **Retrospective items** (docs/18 Section D). The dead-letter repair was
   **checked on 2026-07-26 and this database has nothing to fix** — all
   three rows are already redacted, so every one was written after the
   fix. That closes it *here* and not on any deployment that ran the code
   before migration 0040. Still open: batches accepted before object
   storage was wired cannot be re-parsed, and whether the original
   exposure is reportable — which "we found nothing left on this machine"
   does not answer.

---

## Verified gaps the scoreboard misses

Added 2026-07-26 after a code-level audit that checked **call sites**
rather than existence. Every row below was confirmed by direct search, and
every one sits inside a phase this file scores at 88–100%.

The scoreboard's own definition of the UI dimension is *"reachable and
usable in the browser, not only by `curl`"*. These are the places that
test is failing while the row shows ✅ — a service with tests and no
caller scores 45% of a phase and delivers nothing.

| Gap | Phase | Status |
|---|---|---|
| **Tags and node sets are a dead subsystem.** Schema (0009), `TagService` + `NodeSetService` and five green tests; no router, no endpoint, no UI. The only call sites were its own tests. | 1 | ✅ **CLOSED 2026-07-30.** `routers/curation.py`, 10 endpoints, `curation.manage` (0053); tag chips, apply, remove and create in the inspector. Verified endpoint and browser. |
| **Nothing ever verifies the audit chain.** Phase 0's exit criterion is *"every action appears in a **verifiable** audit chain"* and nothing ever recomputed it. | 0 | ✅ **CLOSED 2026-07-30.** `audit_verify.py` + `GET /audit/verify` + a CI step that runs after the suite. Proven to FAIL correctly: an in-place edit is one CONTENT break, a deleted row one LINK break. **UI added the same day**: Governance → Audit chain, button-driven (it is an O(n) SHA-256 over every event, so load-on-open would be a self-inflicted DoS on the surface an officer reaches for during an incident). A 403 is explained rather than bannered — `audit.read` is SECURITY_OFFICER's alone, so most accounts are refused and that is the design working. |
| **Node and edge "CRUD" is create-and-read only.** A mistyped label was permanent. | 1 | ✅ **CLOSED 2026-07-30.** `update_node` / `update_edge` / `soft_delete_node` / `soft_delete_edge`, each assertion-backed, retiring via `deleted_at` (never `valid_to` — that is temporal validity and using it would rewrite the past). Service + router, **and a UI** (2026-07-30): Correct… / Retire… on the selected element, with the tie cascade reported in a banner. |
| **Case metadata, assignment and closure had no router.** A case could not be corrected, shared or closed from a browser. | 1 | ✅ **CLOSED 2026-07-30**, API **and UI** — Case… / Share… / Status… in the appbar. Lowering a case's classification is deliberately REFUSED — it declassifies everything protected only by the case label, in one statement, under a verb described as "edit metadata". It needs its own verb. |
| **The sociogram could not show a 2,000-node case.** Hard-capped at 800 while the API served 5,000. | 2 | ✅ **CLOSED 2026-07-30.** Analyst-raisable 800 → 2000 → 5000 from inside the truncation notice. The warning stays at every ceiling. |
| **Evidence linking was API-only.** | 1 | ✅ **CLOSED 2026-07-30.** The read path was never broken; there was no way to CREATE a link outside `curl`, so the panel could only ever be empty. |
| **Metric history is API-only.** Phase 3's checklist calls a rising betweenness trend *"visible"*; it was visible to `curl`. **The route is `GET /analytics/history/{node_id}` (`routers/analytics.py`), NOT `metrics/history`** — this file said the latter until 2026-08-10, so anyone grepping the string it gave them concluded the endpoint had never been built. | 3 | ✅ **CLOSED 2026-08-10.** A Trend control per actor row, charting every completed run at the caller's visibility: canvas (the CSP leaves no inline style to place a point with), `aria-hidden`, with a table twin carrying every exact value so nothing exists only in pixels. The series is reversed before charting — the API orders newest-first and charting it as it arrives inverts every trend. **A known limit, disclosed in the pane rather than papered over:** `analytics_runs` writes no row when a metric is undefined for a node and `node_metric.value` is NOT NULL, so an undefined run is ABSENT from the series, not null — and absent cannot be told from "no run happened" at this endpoint. The line spans such a period, and the help text says a long straight segment is not evidence that nothing changed. (An earlier draft of this row claimed the path *breaks* across those runs. It does not and cannot; the break is a guard against an unrenderable value. Corrected before the claim shipped.) Approximate runs are marked in both views; the preset is printed per POINT, since weights are not comparable across parameters. **Verified in the browser 2026-08-10** — the chart rises left-to-right for a rising series (pixel-sampled: left y=70, right y=9), confirming the reversal. |
| **`sigma.js` is not in the tree.** Replaced by a hand-written Barnes-Hut worker for CSP reasons — a good decision that `docs/09-roadmap.md` no longer misdescribes. | 2 | ✅ Documented. |

### The 2026-08-07 error-handling audit

A second pass, 34 agents, scoped to *what happens when this fails*:
**22 confirmed after refutation.** Six were fixed on the day of the audit —
the purge that never touched the object store, `safe_detail` unwrapping
only one level, the 71 rule-1 leak sites, the audit-verify 403 asserting a
role fact, a purge response that could read as a destruction, and CI
failing on chain forks.

The pattern worth naming: **most are a failure that is reported as the
wrong thing**, not a crash.

**Eight more were closed later the same day**, each with a regression test
confirmed to fail against the commit before it:

| | Where | What | |
|---|---|---|---|
| CRITICAL | `app.js` | Sample rejection reported "the bytes are gone" even when the analyst ticked *Keep* — the LEGAL HOLD path, reached because somebody has been ordered to preserve the material. Also: the service now REFUSES to record `bytes_purged: true` with no store attached, which was the third instance of that exact defect (`retention._purge_evidence`, `ingest._with_raw`, here). | ✅ |
| HIGH | `collection.py` | A run that failed after the fetch stayed RUNNING for ever. The row is INSERTed on an autocommit connection so it survives the unwind, and `(status) WHERE status IN ('QUEUED','RUNNING')` is read as "in flight". Same defect `analytics_runs` CR9 fixed, in a second service. | ✅ |
| HIGH | `collection.py` | A watch with an invalid regex was silently dead for ever. The run is now `PARTIAL` — a status that already existed in the enum and was never written by anything. | ✅ |
| HIGH | `deception.py` | An attachment that could not be decoded was recorded as a genuine zero-byte attachment. A forwarded mail carried as an attachment (`message/rfc822`, the standard thread-hijack BEC shape) hits it every time. Both columns are nullable; "unknown" was always representable. | ✅ |
| HIGH | `deception.py` | An unreadable `Authentication-Results` header was reported as no header being present — *with* the reassurance that "their absence is not a failure". And on screen every non-PASS verdict was painted as a failure, so a DKIM `TEMPERROR` (a DNS timeout at the receiving MTA) read as an adverse attribution against the sender. | ✅ |
| HIGH | `graphview.py` | A failed path recompute was swallowed, leaving the previous projection's verdict on screen. The false-negative direction is the dangerous one: an earlier NOT CONNECTED survived into a projection that would have connected the two. Connectivity is now explicitly UNKNOWN, a third state. | ✅ |
| MEDIUM | `install.*` | Wrote `.env.local` from unchecked subprocess output, so a failed key generation produced an empty secret — and the failure LATCHED, because every later run reports "already exists, left untouched". | ✅ |
| MEDIUM | `launch.*` | Treated a set-but-empty variable as unset, defeating the `db.py` distinction. The test written for it found a SECOND implementation of the same rule in the same file, with the same gap — the defaults loop, where a blanked `DATABASE_URL` was replaced by the dev-stack DSN. | ✅ |

**Still open:**

| | Where | What |
|---|---|---|
| MEDIUM | `approvals.py`, `break_glass.py` | A four-eyes request that reached nobody returns 201 — `notify_events.approval_requested` counts reach and returns it, and the caller throws the count away; `ApprovalOut` has no field for it and approvals have no UI, so the 201 is the only signal that exists. And exactly three notification writes have no `try`: `approvals.request`, `approvals.decide` and `break_glass._alert`, each on an autocommit connection AFTER the primary write has committed, so a notify failure turns a completed action into a 500 the router reports as failure. (`merges.py`'s two are inside a transaction on purpose and are correct as they stand.) |

**Closed 2026-08-10** — the two client-side members of that group, each
with a regression test confirmed to fail against the commit before it:

| | Where | What | |
|---|---|---|---|
| MEDIUM | `app.js` | The ingest quarantine latched off **for the session** on any error, not the `ingest.manage` 403 it was written for. A network drop (`ApiError` status 0), a 502, a 503 or a 429 all hid the section until reload with no message at all — a transport failure reported as a permission fact, and reported by making the evidence disappear. It now latches on 403 alone, and a failed read says the queue is *not known to be empty*, because "Nothing unattached" is a claim about the data. | ✅ |
| MEDIUM | `app.js` | All three deception panes reported the error into the counts span and returned before the render, so the list kept the PREVIOUS case's rows — case A's defanged attacker URLs, BEC subject lines and spoofed caller IDs under case B's header and TLP chip. The 403 is the likely path there, not the rare one: all three endpoints gate on `evidence.read`. | ✅ |

`EvidenceStorage.delete()` exists but **has never been exercised against a
live COMPLIANCE lock** — the expected outcome is a refusal recorded as
STORAGE_LOCKED, and that path has no integration test.

### Open findings from the 2026-08-07 hostile pass

33 agents over that day's diff: **17 confirmed after refutation, 11
refuted.** Nine were fixed the same day (the retirement cascade writing
past the caller's clearance, `/audit/verify` answering BROKEN on
untampered history, retention backdating around dual control, the
expiry-nulling upsert, an invented Admiralty grading, a stale tag
vocabulary, a prompt that stated the opposite of what the endpoint does, a
CSP-blocked inline style, and a seeder that could not finish).

These survived refutation. **Five of the seven were closed later the same
day** (migration **0055**), each with a regression test confirmed to fail
against the commit before it:

| | Where | What | |
|---|---|---|---|
| HIGH | `merges.py` | `unmerge` cleared `deleted_at` on every recorded edge unconditionally, so reversing an old merge resurrected edges retired for unrelated reasons afterwards — with `deleted_by` still naming the analyst who retired them. **0055** records at merge time which edges the merge itself deleted; the backfill reconstructs that decision exactly for existing rows rather than defaulting them, because a `DEFAULT false` would have stopped an old merge restoring its own self-loop, which is the opposite defect. Pre-existing, and reachable only since retirement got a caller. | ✅ |
| MEDIUM | `curation.py` | `TagService.assign` had no `ON CONFLICT` against 0054's indexes. The conflict target has to restate the partial index's predicate — 0054 created four partial indexes deliberately, and a partial index is not usable as a conflict target without its `WHERE`. | ✅ |
| MEDIUM | `cases.py` | A naive (offset-less) `expires_at` 500d on `TypeError`. Refused with a 400 rather than assumed to be UTC: this decides when somebody LOSES access to a case, and 17:00 local read as 17:00Z is thirteen hours of unintended access with nothing saying which reading was taken. | ✅ |
| LOW | `curation.py` | `merged_into_id` was filtered in `list_tags`' count but not in `list_sets`, `list_members` or `_visible_node`. Merged-away members are now returned under `merged_away` rather than folded into `withheld` — a merge is not a clearance fact, and the ids have to stay reachable or the entry can never be removed. | ✅ |
| LOW | `graph.py` | Eight sites (not the two originally reported) raised `GraphWriteError(str(exc))`, putting constraint names and offending column VALUES into the message. `safe_detail` already covered the HTTP boundary; the message itself is now clean, so logs, stored columns and scripts are too. The cause chain is preserved. | ✅ |

**Still open:**

| | Where | What |
|---|---|---|
| MEDIUM | `audit_verify.py` | A row inserted with `prev_hash NULL` passes every check — the genesis row is exempt by construction, so a second "genesis" is invisible. The chain has no anchor saying which row is first. |
| MEDIUM | `cases.py` | Raising a case's classification can strand its owner above their own clearance, and there is no route back — lowering is refused by design. |

### The migration round-trip is only proven on an EMPTY database

Verified 2026-08-07. `alembic downgrade base` → `upgrade head` passes on a
freshly migrated database, which is the contract CI checks and it holds.
Run the same round-trip against a database **with data in it** and it
fails:

```
ForeignKeyViolation: update or delete on table "role" violates foreign key
constraint "case_assignment_role_key_fkey"
DETAIL: Key (key)=(CASE_OWNER) is still referenced from case_assignment.
```

`0017.downgrade()` does `DELETE FROM iam.role WHERE key IN (…)`, and
`iam.case_assignment.role_key REFERENCES role(key)` **without**
`ON DELETE CASCADE` — unlike `iam.role_permission` two lines above it in
0012, which has one. So the seed cannot be unwound on any deployment that
has ever assigned a case.

Not fixed, and arguably not worth fixing: downgrading past 0017 unwinds
the entire ontology and role seed, which on a live database is data
destruction rather than a rollback. But CONVENTIONS.md says "every
migration must be reversible", CI proves that only for the empty case, and
the difference is exactly the kind of thing somebody discovers during an
incident. Recorded rather than left to be rediscovered.

> **CLOSED AS DELIBERATE, 2026-08-10 — the document was wrong, not the
> migration.** Two corrections to the paragraph above. First, it is not one
> foreign key: there are **five** into the seeded rows
> (`iam.case_assignment.role_key` and `iam.user_role.role_key` among them),
> with a second instance of the same shape in `0031`. Fixing "the" FK would
> have moved the failure one constraint to the right and looked like
> progress. Second, the refusal is the DESIGNED behaviour — adding
> `ON DELETE CASCADE` to make the downgrade pass would silently delete
> graph and authorization data to make a rollback succeed, straight through
> the soft-delete-only invariant. **`CONVENTIONS.md` has been corrected**
> to say reversible-on-an-empty-database, which is what CI proves and what
> the migrations actually promise. If you need to go back past 0017 on a
> live database, restore a backup.

### Found while closing them

- **Notifications were queued on the wrong clock.** `deliver_after` came
  from `datetime.now()` and is compared against Postgres `now()` — two
  clocks in one comparison. The host here was **3.79s ahead** of the
  container, so every non-urgent delivery was ~4s in the future by the
  reader's reckoning and an immediate drain found nothing. In production
  the API and database routinely sit on different hosts, so the same skew
  silently delays or prematurely releases every notification. Fixed:
  the base time now comes from the database.
- **`NodeSetService.add_member` destroyed notes.** `SET note =
  EXCLUDED.note` meant re-adding a member without a note wrote NULL over
  it — a double-click away, on the one field in a working set that cannot
  be reconstructed from the graph.
- **`core.tag_assignment` had no key and no unique index** (0054), and
  **`core.edge` had no `deleted_by`** while `core.node` has had one since
  0005 (0053).
- **The audit chain has 67 genuine FORKs** on the development database —
  two rows claiming one predecessor, which is the condition 0013's
  advisory lock exists to prevent. Not fixed; worth a look.
- **`seq` order is not chain order.** The first verifier assumed it was
  and reported 68 breaks on honest history — the exact failure a
  tamper-evidence tool must never have.

> **REFUTED 2026-08-10, and no migration was written.** An earlier draft
> of this entry blamed the tail selector — `ORDER BY seq DESC LIMIT 1`
> picking a predecessor by an ordering that is not the chain's — and
> proposed migration 0056 to fix it. **Three experiments say the writer is
> sound, so 0056 was NOT written.** Rewriting the hottest write path in
> the system (every audited action across 28 modules) on an unreproduced
> premise would have been the more dangerous act:
>
> | Experiment | Result |
> |---|---|
> | Two connections, one holding the xact advisory lock mid-INSERT | The second **blocked** for a full 2.5s `statement_timeout`. Concurrency is serialised. |
> | `INSERT … SELECT` over three rows in one statement | **Three DISTINCT predecessors.** The BEFORE trigger sees rows already inserted by its own statement. |
> | The live development database | 3,947 rows, **one** genesis, **zero** forks. |
>
> No production code writes `prev_hash` or `row_hash` — the trigger owns
> both — and all three triggers are enabled. The 67 forks were most likely
> the same artefact as the 68 "breaks" this module reported before its
> `seq`-ordering bug was fixed: counted by a verifier that was itself
> wrong. Two of those experiments now ship as tests, so if the property
> ever stops holding, the old explanation becomes correct again and the
> docstring says to change it back.
>
> **What was real, and IS fixed:** the chain had no anchor. A row inserted
> with `prev_hash NULL` passed every check — LINK exempts it by
> construction, FORK filters `prev_hash IS NOT NULL`, and CONTENT
> *blesses* it because the hash input for such a row is the literal string
> `GENESIS`. Demonstrated against the old verifier: forging a second
> "first row" left it reporting **`intact=True, breaks=0, forks=0`**. That
> is the shape of a truncation, and the one thing no relative check can
> see. `verify_chain` now counts genesis rows whole-table (never
> windowed), reports `GENESIS` / `NO_GENESIS` as tampering, and publishes
> `genesis_count`. **The fork split is kept** — a fork still is not proof
> of editing and legacy databases may carry real ones in an append-only
> table — but it is no longer explained away as normal concurrency, so one
> now deserves investigation.
>
> Still open: the same missing anchor in `core.custody_chain_hash()`,
> which has no verifier of any kind and whose docstring invokes
> FRE 902(13)–(14).

**None of this is a regression.** It is the same lesson this file already
records twice: a green suite either side of a contract that neither side
asserts. The measure got honest once when UI was added to the weighting;
it needs to get honest again about *reachability*, because "service +
tests exist" is what several ✅s are currently reporting.

**What I did not re-verify.** A first-pass audit also flagged the Phase 4
collection read path (`collect.document` and `collect.watch_hit` written
by the collector and read by nothing), a suspected key mismatch in the
co-participation renderer, and detail in Phases 5/6/9. The adversarial
stage that would have refuted or confirmed those did not complete. They
are **unverified leads, not findings**, and are recorded here as such
rather than being either dropped or dressed up.

> **RESOLVED 2026-08-10. Both leads were CONFIRMED, and one was worse than
> the lead said.**
>
> - **The co-participation renderer.** Not "renders nothing": it rendered
>   the literal string `undefined — undefined` on every row, with a
>   correct weight and a correct *inferred* chip beside it, so the pane
>   looked populated and was unreadable. It read `t.source`/`t.a` and the
>   service emits `src`/`dst`; it read `t.rooms` and the service emits
>   `shared_conversations`; it read `body.warnings`, which the service has
>   never emitted, so the whole `coverage` block was dropped — and that
>   block is where the oversized-room exclusions are reported. The module
>   says "a cap that silently drops data is worse than no cap, because the
>   output looks complete"; in the browser the cap was silent. **FIXED
>   2026-08-10** with four contract tests, one of which asserts the JSON
>   keys across the two files — the check whose absence let it ship, since
>   both sides were individually tested and internally consistent.
> - **The Phase 4 collection read path.** Confirmed and larger than
>   described: no endpoint, no UI, no search reach. `SearchService` covers
>   `core.node` and `core.evidence` only, and `collect.document`'s GIN
>   index is used by no query in the tree. The lifecycle columns prove the
>   intent was never finished — `notified_at`, `suppressed`,
>   `acknowledged_by`, `acknowledged_at` and a partial index for the
>   unnotified set, none of them written or read by anything, and a
>   `triage_state` column with a supporting index and zero references in
>   `apps/api/src`. An analyst sees the integer `watch_hits` on a run card
>   and cannot open one of them. **STILL OPEN** — it needs a service read
>   method, two routers, a subtab and a renderer, and no migration.
>   Related: `CollectionService.run_once` never calls `ProposalStore`, so
>   `collection.py`'s own docstring claim that everything an adapter
>   produces "reaches the graph only through the proposal queue a human
>   works" is false for the collector.

### Found off-roadmap, 2026-08-10

A ten-agent read-only sweep over the items above turned up things that
were on no list. The first is the most serious finding currently open.

**🔴 Break-glass does not raise anything, and its review control counts
nothing.** Verified directly, not inherited from the sweep:

- `break_glass.py` states the guarantee — *"It raises a user's effective
  clearance for one case, for a few hours, with everything above
  recorded."* Nothing implements it. `stores.py` resolves clearance with
  `SELECT tlp_clearance, compartments FROM iam.app_user`, and outside
  `break_glass.py` itself the only mention of the table anywhere in
  `apps/api/src` is a comment in `deps.py` about step-up. So the grant row
  is written, audited and reviewable, and the analyst's effective
  clearance is exactly what it was before they invoked it.
- `record_use()` is defined at `break_glass.py:261` and its only callers
  in the tree are two lines of `test_governance_pg.py`. `action_count` is
  published to the security officer's review queue
  (`routers/governance.py:489`) and is therefore **structurally always
  zero** — the officer reviews "what was done under this grant" against a
  number that cannot be anything else.

Either wire it or withdraw the claim; the middle position is the one that
misleads. Withdrawing is about an hour's work — strike the elevation
sentence, drop `action_count` from the response — and wiring it touches
the single `AccessContext` construction site. **It is not a defect that a
green suite could have caught: the service does what its tests say, and
the tests never asserted that anything reads the grant.**

**Reported by the sweep and NOT individually re-verified** — recorded as
leads in the same spirit as the section above, so they are neither
dropped nor dressed up as findings:

| Where | Lead |
|---|---|
| `merges.py` | A merge that collides with `edge_uniq_active` is said to return 500 rather than 409 — and the commonest real merge, two records sharing a tie to a third party, is exactly the collision case. |
| `retention.py` | `storage_locked` is said to report the batch size rather than the refusal count, on an irreversible destruction record. |
| `merges.py` | `edges_repointed` is said to count merge-deletions as moves. |
| `routers/cases.py` | No transfer-ownership endpoint exists, while the refusal text for lowering a classification tells the operator to use one. |
| `routers/collection.py` | The collection endpoints are said to do no clearance or compartment filtering at all — which any new documents endpoint must not copy, since `collect.document.classification` defaults to AMBER. |
| `notify_events.py` | Three registered notification kinds (`PROPOSAL_QUEUED`, `EVIDENCE_INTEGRITY_ALARM`, `CASE_REVIEW_DUE`) are said to have no producer. |

---

## 🔴 Before anything else: the legal register

`docs/16-legal-and-external.md` holds **5 BLOCKING items, 8 determinations
and 13 things to confirm externally.**

> **Corrected 2026-07-26.** This line said "4 / 7 / 10" and was wrong on
> all three counts. The undercount that mattered was the blockers:
> **L5 — active web capture authority** shipped with the deception
> subsystem and was enforced in the schema, announced in README,
> SECURITY.md, ARCHITECTURE.md and docs/19 — and recorded in neither
> docs/16 nor the counsel pack in docs/18. Both documents a lawyer
> actually reads said four. A reviewer working from that pack would have
> cleared the platform without being asked whether entering input into a
> phishing page is authorised. L5 and A5 now exist in both, each carrying
> a note that an earlier review did not cover them.

The five blockers, compressed:

| | What | Why it blocks |
|---|---|---|
| **L1** | Prohibited-content policy for samples | The build refuses ingest until a policy reference and a designated person are declared — but **that is a declaration it records, not one it can verify**. Also: `REJECTED` currently *destroys* the bytes, which is wrong in a jurisdiction requiring preservation. |
| **L2** | Stealer-log lawful basis, victim notification, real retention | Holding data about thousands of uninvolved people. 90 days is a placeholder. |
| **L3** | Persona operation authority | The software will drive an account into a forum. Whether you may is not a software question. |
| **L4** | Interception law and consent | Message capture. `provenance_class` records *which* kind; the authority is external. |
| **L5** | Active web capture authority | Fetching attacker infrastructure discloses the investigation; **entering any input into a phishing page, including canary credentials, may constitute unauthorised access.** The schema refuses to record a submission without a written authority reference. Nothing is automated. |

The thirteen **CONFIRM EXTERNALLY** items include evidence-authenticity standards
(reasoned from the rule text, not from a practitioner), MinIO COMPLIANCE
semantics on your actual object store, and the platform durable-identifier
mappings — which change, and where a stale mapping produces confident false
attribution.

---

## Prioritised engineering work

### 1. ~~An adversarial review pass over every phase~~ — done 2026-07-26

**Every phase has now had one**, and every pass found a real defect. The
last two were Phases 5 and 8 (docs/17 **F19**): 27 findings survived
refutation, nine CRITICAL, all fixed with regressions. Phase 8 had 673
green tests and shipped a security control that did not exist — its
"encrypted archive" was a plain ZIP, and its download endpoint applied no
label check at all.

What is left on this axis is **Phase 6**, whose review is partial, and a
pass over this session's own fixes. That second one is not
belt-and-braces: the 2026-07-25 evening pass found that *most of its
findings were in the previous pass's fixes*, and this session repeated the
pattern — a filename defence written that morning was defeated by the
exact attack it was written for, and only a screenshot showed it.

### 1b. The pattern, for whoever runs the next one

**Phase 7's is done** (2026-07-25) and the pattern held again, harder than
before. Three reviewers with distinct lenses, every finding then put
through an independent refutation round, produced:

- a **forged PGP verdict** — a crafted OpenPGP user ID smuggled a
  `[GNUPG:] VALIDSIG <victim>` line into the status stream through
  characters `str.splitlines()` treats as line breaks and gpg does not
  escape, minting a CONFIRMED binding for a key the attacker never held;
- **Newman weighting divided by the filtered participant count**, so two
  people in a 500-member channel scored exactly as high as a private DM;
- a **label defence that was structurally ASCII-only**, so `Гарант:` —
  the standard guarantor label on the Russian forums that are this
  domain's primary venue — was attributed to the vendor while the
  transliterated `Garant:` was caught.

All three sat under a fully green 953-test suite. The first was invisible
on the Windows dev host and live on the Linux deployment target.

Phases 4 and 9 have still had none. The cheapest lens, and the one worth
running first: **diff two implementations of the same rule against each
other.** It found the normaliser divergence in seconds, where every unit
test passed on both sides because each was internally consistent.

### 2. ~~UI for the phases that had none~~ — done 2026-07-26

Every phase now has a pane. The **Lab** pane was the last, and it was
built after Phase 8's adversarial pass rather than before, deliberately:
fixing a model defect once its UI exists costs the UI too, and that pass
changed three service signatures.

Five things the panes taught, worth carrying into anything added next:

1. **`Promise.all` over endpoints with different permissions is wrong.**
   The first 403 rejects the lot, so a caller who holds four of five
   permissions sees an empty pane claiming they hold none. Load each
   section independently and say where it is refused.
2. **A permission error is not an empty state.** "Nothing here" and "you
   may not see what is here" are different facts and an analyst acts on
   them differently.
3. **Look at it rendered.** Five defects across this work were invisible
   to the suite and obvious on a screenshot in ten seconds: an alert list
   padded with never-polled sources; a `Promise.all` whose first 403
   blanked a tab; a purge screen reading a key the server never sends; a
   staggered animation that hid twenty-five of twenty-eight rows; and a
   right-to-left override that defeated the very control written to catch
   it.
4. **`textContent` stops a string EXECUTING and does nothing about it
   LYING.** Bidi overrides, zero-width characters and controls change what
   a string looks like without changing what it is. Substitute them at the
   data boundary — there are two dozen sites that draw a node label and
   one of them will always be the one somebody forgot.
5. **Motion must never be load-bearing.** `animation-fill-mode: backwards`
   with a delay holds content invisible; if the animation clock stalls,
   rows are simply missing with no error. Everything in `app.css` now
   animates from a visible resting state.

### 3. ~~HTTP routers for Phases 4, 6 and 9~~ — done 2026-07-25

Every service now has a router. What is left on this axis is the UI.

### The sequence I would actually follow

Ordered so each step makes the next one cheaper, with the completion
gain each buys.

| # | Work | Buys | Why here |
|---|---|---|---|
| ~~1~~ | ~~Routers for 4, 6 and 9~~ | done 2026-07-25 | Every service has a router. |
| ~~2~~ | ~~Adversarial pass over 4 and 9~~ | done 2026-07-25 | Ten service defects, all now fixed at the service. |
| ~~3~~ | ~~Adversarial pass over 5 and 8~~ | done 2026-07-26 | 27 findings, nine critical, all fixed (docs/17 F19). Every phase has now had one. |
| ~~4~~ | ~~UI for 7, 6 and 8~~ | done 2026-07-26 | Every phase has a pane. |
| 1 | **Close the per-phase feature gaps** below | ~**+5%** | Adapters, WebAuthn, Jira, fuzzy hashing. Genuine feature work, and the part most exposed to the legal blockers. |
| 2 | **A hostile pass over Phase 6, and over this session's own fixes** | ~**+2%** | Phase 6 is the last phase with a partial review. And the fourth pass's lesson stands: most of its findings were in the previous pass's FIXES. |
| 3 | **The remaining retrospective items** (docs/18 Section D) | 0% on this scale | The dead-letter repair is checked and clean on this database (2026-07-26). What is left: batches accepted before object storage was wired cannot be re-parsed, and whether the original exposure is reportable. Neither scores; both are real. |
| 4 | **The deferred security items** | 0% on this scale | Scores nothing and matters anyway: session binding, RLS under a non-owner role, DNS-rebinding-proof SSRF protection, login timing. |

That reaches roughly **98%** with no phase below 85%. The last 2% is
CONCOR, metric-history charting, and the two-mode presets for actor×forum
and actor×wallet.

**None of it changes the four BLOCKING legal items.** A 98% build is still
one that must not be operated until L1–L4 are settled.

### 4. The remaining per-phase work

- **Phase 4** — XenForo, MyBB, Telegram MTProto adapters (each blocked on
  L3 as much as on code); document embeddings; a scheduler process.
- **Phase 5** — Jira, the integration admin surface (the `notify.delivery`
  ledger records every refusal with a reason, and now the address each
  message actually reached, and nothing renders any of it), escalation of
  an unacknowledged priority-1, a worker.
- **Phase 6** — WebAuthn, timeline replay, the assumptions register.
- **Phase 7** — done except the UI. What remains is genuinely optional:
  loose matching of a differently-formatted identifier inside a signed
  payload (deliberately not done — a false confirmation costs far more
  than a second look), detached-signature support alongside clearsigned,
  and a keyserver-free way to obtain a vendor's public key.
- **Phase 8** — imphash/ssdeep/TLSH (each a dependency; ssdeep needs a C
  toolchain on Windows), YARA, capped archive expansion, sandbox
  integration. Every absence is already recorded on the sample row as a gap
  with a reason, and the Lab pane renders those gaps before it renders any
  finding — an analyst reading findings needs to know what was never
  looked at.
- **Phase 9** — the outbound credential vault with per-provider quota and
  exposure levels. *(The 202 wiring and object storage are done —
  `rawstore.py`, 2026-07-25.)*

### 5. Security items still deferred

| Item | Note |
|---|---|
| DNS-rebinding-proof SSRF protection | `fetch()` now re-validates every redirect hop and classifies addresses by what they ARE rather than by an enumerated list, but the name is still resolved once here and again by the socket layer. The real fix is a proxy enforcing policy at connect time. |
| Session IP/UA binding | A stolen token is portable |
| Non-owner DB role + RLS | The API connects as the table owner, so RLS is a no-op behind it |
| Login timing equalisation | A missing account returns faster than a wrong password |
| Compartment registry | Free-text; a typo creates silent no-access |
| CI typecheck | No annotations to check against |
| Redis isolation | The limiter shares an instance running `allkeys-lru` |

---

## Open questions for the operator

- **Ingest key holders** — internal scripts only, or external partners?
  Changes the support and abuse model (docs/16 D6).
- **Expected ingest volume.** Above ~1M records/day the bucket needs a
  different storage tier.
- **Which sandbox vendors count as "private"** for detonation exposure —
  several "private" tiers still share hashes with partners.
- **Who is the security officer?** Break-glass *refuses to grant* if no
  active user holds `SECURITY_OFFICER`.
- **Retention periods.** Six placeholder rules ship in migration 0032, and
  purge warns loudly on every one nobody has confirmed.

---

## Traps worth carrying forward

- **The test count is TWO roots.** `apps/api/tests` and
  `packages/ontology`. Run both or the number will not reconcile with this
  file, which is how a previous session lost twenty minutes.
- **`alembic` must be run from the repo root.** `alembic.ini` lives there,
  not in `db/`, and running it from `db/` fails with "No 'script_location'
  key found in configuration" — which reads as a broken install and is
  not.
- **An append-only ledger outlives its subject, so teardown must check and
  skip.** `lab.sample_access`, `core.evidence_custody`,
  `core.purge_tombstone` and `audit.event` all raise on DELETE **and**
  carry foreign keys to the thing they describe. So a test that ingests
  evidence can never delete that evidence, its case, or the user named on
  the custody row. Four separate suites have now learned this the same
  way.
- **A CSS character class of literal invisible characters will be
  mangled.** It happened between writing the bidi defence and it landing on
  disk. Declare them as `\uXXXX` escapes — that is also the only form a
  test can assert on.
- **`animation-fill-mode: backwards` plus a delay hides content.** Not
  "briefly": for the whole delay, and indefinitely if the animation clock
  stalls — which a hidden tab already causes in this app.
- **`--out` is not covered by `.gitignore` just because the default is.**
  `screenshot_ui.py` now refuses an un-ignored directory inside the repo,
  after fifteen renders of a live case sat untracked in the working tree.
- **uvicorn runs WITHOUT `--reload`.** A new route 404s until restart.
- **TOTP cannot work on this host** — unsynchronised clock, in 2026. Use
  `bootstrap.py session --email <you>`.
- **TOTP codes are single-use.** Two logins in one 30-second step fail on
  the replay guard, not on the code under test.
- **Constraints tie fields together and fire on UPDATE.** A case cannot be
  created already expired; a break-glass grant cannot be aged past 8h; an
  ingest key cannot expire before it was issued. Age the *pair*.
- **`array_length('{}', 1)` is NULL, not 0.** Any `>= 1` check on an array
  needs `coalesce` or it silently passes on the empty case — this shipped
  as a real bug in the stealer-log compartment check.
- **A partial unique index needs its predicate restated in `ON CONFLICT`.**
- **Retention rules are GLOBAL.** A test that confirms one leaks into every
  later test. **The comms service stoplist is global in exactly the same
  way** — tests use a reserved `*.cbstop.test` domain so teardown can find
  the rows, because a leaked entry surfaces as a unique violation in an
  unrelated test.
- **Teardown order follows the foreign keys, not the reading order.**
  `comms.contact_block_entry.stoplist_id` references `service_selector`,
  so deleting the stoplist first leaves teardown failing on an FK — and a
  failed teardown leaks the global row the next trap is about.
- **`iam.case_assignment.granted_by` is NOT NULL.** A test that inserts an
  assignment by hand has to supply one.
- **gpg-agent does not autostart on this host.** `gpgconf --launch
  gpg-agent` fixes it. Only SECRET-key operations need it: verification is
  public-key only, which is why the PGP tests run against vendored
  fixtures and never generate a key.
- **The Windows `gpg` on PATH is the MSYS build shipped with Git and it
  expects POSIX paths.** Handed `C:\...` it resolves the path against its
  own cwd and reports a perfectly good key as unreadable. `pgp.py` passes
  RELATIVE paths with an explicit `cwd` for this reason; do not "tidy" them
  into absolutes.
- **Do not run the suite while background agents run theirs.** The e2e
  cleanup deletes by email pattern and concurrent runs delete each other's
  fixtures. The failures look real and are not.
- **A hidden browser tab clamps `setTimeout` to ~1s** and suspends
  `ResizeObserver`.
- **A unique index over NULLABLE columns needs `coalesce`.** Two NULLs
  never conflict, so the duplicate the index exists to prevent is
  inserted twice and the list looks like protection while providing it
  twice over.
- **`alembic downgrade base` succeeds on a CLEAN database and stalls
  around 0017 on the dev one**, which has accumulated test data. CI runs
  the round-trip before the tests on an empty database, so it passes
  there — but running it against your working database will leave it
  half-migrated and every test failing until you `upgrade head` again.
  To check the chain, use a scratch database and install the extensions
  first: `vector`, `pg_trgm`, `pgcrypto`, `btree_gist`, `citext`,
  `uuid-ossp`. Without them the chain dies at 0004 with "type vector does
  not exist", which reads as a migration bug and is not one.
- **Check the claim, not just the code.** The dead-letter redactor's
  docstring said the verbatim bytes remained in the batch's raw object,
  which is the whole reason redacting the fragment is safe rather than
  lossy. It was false: `accept()` stored the payload only when given a
  storage adapter and every caller passed none. The defect was found by
  writing the sentence down and then going to check it.
- **A locale can hide a security defect.** The PGP status-injection flaw
  was live under UTF-8 and inert under this host's cp1252, so the dev
  machine and CI would have disagreed about whether the system was
  exploitable. Where a defence depends on how bytes decode, assert on the
  BYTES.
