# Session handoff — 2026-07-25

Written so a fresh session can resume without re-deriving anything.

> **Read order for a new session:** this file, then `CLAUDE.md` (the twelve
> invariants), then `docs/15-handoff.md` (the durable project handoff — this
> file is the *session* record; docs/15 is the *project* record and outlives
> it). `docs/00-decisions.md` now holds 42 numbered decisions; 30–42 were
> taken in this session.

---

## 1. Context & Objective

**NocTORnal** is a HUMINT / social-network-analysis platform for cybercrime
investigation: analysts build a graph of criminal actors, personas, groups and
the trust between them, every element traceable to graded evidence with a chain
of custody. Comparable to Maltego, i2, SL Crimewall, with UCINET-grade SNA
maths. Python 3.13 / FastAPI / Postgres 16, plain-HTML analyst UI under a strict
CSP with no build step.

**This session's objective**, as given: *"We are beginning with phase 3"*, then
*"push through phase 3 entirely"*, then *"enhancements for E-items and visuals…
continue with the phases using your best judgement"*, then *"continue phase by
phase until the context has run out"*.

So: Phase 3 in full, then the enhancement map's E-items, then as much of Phases
4–6 as could be built **well** rather than broadly.

**Three ideas everything follows from** (docs/01), all three of which now have
enforcement rather than aspiration:

1. **A handle is not a person.** `IDENTITY` vs `PERSON`, joined by a reversible
   confidence-scored `ATTRIBUTED_TO` edge.
2. **Nothing is a fact.** Every element traces to an `assertion` with an
   Admiralty grading.
3. **Machines propose, analysts dispose.** Extractors write `proposal` rows,
   never graph elements.

---

## 2. Completed Work

### Before this session

Phases 0–2: Alembic-owned schema (0001–0025), Argon2id + TOTP auth, the
five-part access gate as one `evaluate()`, the assertion layer enforced by
deferred DB triggers, WORM evidence with a hash-chained custody ledger, cases,
selectors, tags, node sets, full-text search, and the Phase 2 sociogram
(four projection presets, ego networks, paths, `as_of` scrubber, local metrics,
saved layouts, command palette, inspector). **254 tests.**

### Built this session — 11 commits, 54 files, ~9,300 insertions, 254 → 421 tests

**Phase 3 — analytics (commit `d2f1696`).** `analytics.py` (pure, database-free,
so the maths is testable against hand-computed values) + `analytics_runs.py`
(cache, `metric_run` lifecycle, audit). Betweenness with Brandes pivot sampling
above 3k nodes, harmonic closeness (classical is undefined on disconnected
graphs, which criminal networks routinely are), eigenvector over the *positive*
subgraph only, Burt's constraint/effective size/efficiency/hierarchy, Leiden
communities, cut vertices, bridges, signed structural balance with unbalanced
triads and contested dyads, KPP-Neg key player. Rank + percentile on every
value. Alembic **0026**. Analysis tab in the UI.

**E-items + visual layer (commit `32af626`).**
- **E1/E2** — exhibit attachable at the moment a claim is made
  (`assertion.evidence_id` had been unused since Phase 1); projection reports
  `has_evidence`; unevidenced entities render hollow, unevidenced ties fade;
  case-level coverage is a headline number that reads red at zero.
- **E3** — retraction in the inspector. Retracting the last live assertion
  visibly dissolves the element from the live graph.
- **E4** — recovery codes: 10, single-use, Argon2id, told apart from a TOTP
  code by *shape* so login stays single-step; single use enforced by an atomic
  `array_remove` guarded on the hash still being present.
- **U1** — hand-written ForceAtlas2 + Barnes-Hut in a Web Worker.
- **U3** — `valid_from` / `valid_to` on the entity and relationship forms.

**Phase 5 egress gate + Phase 4 proposal pipeline (commit `022d9e5`).**
`egress.py` is the one `can_egress()` docs/07 requires; evidence export now
calls it instead of its own drifting copy. `proposals.py` enforces invariant 3
**by class shape** — the extractor-facing `ProposalStore` holds no
`GraphWriteService` and cannot reach the graph; a test asserts that.

**Manual capture + triage (commit `519e487`).** `extraction.py` lands pasted
text as a `collect.document` deduped on content hash, writes
`collect.extraction` rows **with character offsets**, and raises one proposal
per new value carrying the sentence it came from. Keyboard-driven Triage tab
(J/K move, A/R/D dispose) with a rail badge.

**Entity merge (commit `c0cf1f0`, Alembic 0027)** and its **UI (commit
`298739f`)**. A ledger, not a flag: `core.node_merge` + `node_merge_edge` record
every re-pointed endpoint so reversal is a *restore*, not a re-derivation.

**CI (commit `27713e8`).** Four gates + `ruff.toml` + `check_source_hygiene.py`.

**Fixes.** Sociogram resize (commit `3fe93ff`) and `scripts/open-ui.ps1`
(commit `9df9bf8`).

### Bugs found and fixed that were NOT in the brief

1. **Retraction was cosmetic.** Decision 24 scoped live provenance as a
   *projection* property rather than a DB constraint — and the projection never
   implemented it. A retracted assertion showed a RETRACTED chip while its node
   kept full degree, so Phase 3 would have named takedown targets from
   withdrawn evidence. Fixed in `projections.py`.
2. **`Subgraph.truncated` was computed and dropped**, making a metric over a
   cut-off node set indistinguishable from a complete one. Key player now
   *refuses* on a truncated projection.
3. **A fail-open default in migration 0026**:
   `visibility_compartments NOT NULL DEFAULT '{}'` is exactly what an analyst
   holding no compartments looks up with. Both columns are now NOT NULL with no
   default. A later round-trip test found a *second* defect in the same
   migration — it only applied to an empty table.
4. **The sociogram vanished below ~900px** (canvas row had a floor of `0`).
5. **A `zip()` without `strict=`** in `_mode_warning` would have silently
   mislabelled which vertices are non-actor (found by ruff).

---

## 3. Current System State

| | |
|---|---|
| **Branch** | `main`, working tree clean, nothing pushed (no remote configured) |
| **Migration head** | `0027`, round-trips head → base → head |
| **Tests** | **421 passing**, 0 failing, 0 skipped with the stack up |
| **Lint** | `ruff check` clean; source hygiene clean (143 files) |
| **Ontology** | generated TS + SQL match the definition |
| **Python** | **3.13.14** — *not* the 3.12 the docs assume |
| **Stack** | Docker Compose: postgres, redis, nats, minio, openfga, mailhog |

### Key architectural decisions (30–42 in `docs/00-decisions.md`)

- **30 — Analytics run SYNCHRONOUSLY in the API**, not in the Zone B worker
  docs/02 describes. A queue adds a process, a dependency and a progress UI
  without changing a number at this scale (2k nodes / 6k edges = 1.15s). The
  compute layer is pure, so moving it later is a change of *caller*, not
  algorithm. **Accepted caveat: CPU-bound path behind a non-step-up permission
  with rate limiting still deferred.**
- **31 — A metric run is cached against the CALLER'S VISIBILITY.** `project()`
  filters by clearance, so a cached betweenness computed over RED nodes served
  to an AMBER analyst would leak structure. Two independent mechanisms.
- **35 — Phase 7 is MESSAGE-LEVEL capture** (operator decision).
- **36 — NO prohibited-content policy exists → Phase 8 is BLOCKED.**
- **41 — Merge is a ledger; IDENTITY may never merge into PERSON.**
- **42 — CI lint rule set is deliberately small** (E/W/F/B, B008 ignored:
  FastAPI's `Depends()` idiom fired it 157 times on correct code).

---

## 4. Immediate Next Steps & Pending Work

Prioritised. Items 1–3 close gaps this session created or named.

1. **Rate limiting** (deferred security item; decision 30 names analytics as a
   DoS surface for an authenticated analyst). Redis is in the stack and unused.
   Decide fail-open vs fail-closed when Redis is down — that is the real
   question, not the implementation.
2. **Dual control on merge** (docs/01 asks for it; only step-up is built) and
   the **case-owner notification** on merge (blocked on item 3).
3. **Phase 5 proper**: SMTP with digest/suppression/quiet hours, in-app
   notification centre, Jira, webhooks. The egress gate they all must call
   already exists and is tested.
4. **U2 — "why is this hidden"**: an under-cleared analyst sees a smaller graph
   with no indication anything was withheld. Needs care — a bare count is itself
   a weak signal, so it may need to be a per-case setting.
5. **Phase 6 remainder**: ACH matrix, report builder with TLP-aware redaction
   (high value for decision 13's prosecution-grade posture, and it would use the
   egress gate), retention/purge with tombstones, WebAuthn, break-glass.
6. **Phase 4 remainder**: adapter interface + scheduler, RSS adapter first,
   persona vault, watch matching, parser health checks. **Do not start until the
   graph layer has been used in anger on a real case** — docs/09 is explicit
   that a firehose into a half-built model produces a landfill.
7. **Phase 7** (message-level capture, decided) and **Phase 9** (ingest API).

### Blockers and open questions

- **Phase 8 is hard-blocked** on the prohibited-content policy. See the warning
  block at the top of `README.md`. Nothing in the build stores a sample; keep it
  that way until counsel settles the policy.
- **Two-mode presets.** Financial includes `CONTROLS`/`TX_*` and Communication
  includes `PARTICIPANT_IN`, so `WALLET`/`TRANSACTION`/`CONVERSATION` become
  graph vertices. The analytics response *warns* (decision 33) rather than
  silently rewriting the presets, which would change every Phase 2 number.
  Proper bipartite→one-mode with Newman weighting is unbuilt.
- **Per-case trust-decay default** has no home; the half-life is a request
  parameter stored on the projection. `core."case"` has no column for it.
- **Metric history endpoint exists and is tested, but nothing charts it.**
- **Still no typecheck in CI** — there are no annotations to check against, and
  a mypy job that passes vacuously is worse than an absent one.

### Traps that cost real time this session

- **uvicorn runs WITHOUT `--reload`.** A new route 404s until restart. This bit
  me *twice* despite being documented in docs/15.
- **A hidden/background browser tab clamps `setTimeout` to ~1000ms and
  suspends `ResizeObserver` callbacks.** I spent effort "fixing" main-thread lag
  that was pure measurement artifact. Count messages and repaints, not wall time.
- **Test cleanup order matters**: `core.assertion` and `collect.proposal` both
  reference `collect.document`, and the deferred invariant-1 triggers fire at
  commit — so assertions and their elements must be deleted in ONE transaction.

---

## 5. Relevant File Paths & References

### New this session

| Path | What |
|---|---|
| `apps/api/src/noctornal_api/analytics.py` | The SNA maths. Pure, no DB. |
| `apps/api/src/noctornal_api/analytics_runs.py` | Cache, `metric_run` lifecycle, audit |
| `apps/api/src/noctornal_api/egress.py` | The one `can_egress()` (invariant 8) |
| `apps/api/src/noctornal_api/proposals.py` | Invariant 3, enforced by class shape |
| `apps/api/src/noctornal_api/extraction.py` | Paste → document → extraction → proposal |
| `apps/api/src/noctornal_api/merges.py` | Reversible merge |
| `apps/api/src/noctornal_api/security/recovery.py` | Recovery codes |
| `apps/api/src/noctornal_api/http/routers/` | `analytics.py`, `proposals.py`, `merges.py` |
| `apps/api/src/noctornal_api/http/static/layout-worker.js` | ForceAtlas2 + Barnes-Hut |
| `db/migrations/versions/0026_analytics_runs.py` | Analytics run storage + cache safety |
| `db/migrations/versions/0027_node_merge.py` | Merge ledger |
| `.github/workflows/ci.yml`, `ruff.toml` | CI and lint config |
| `scripts/check_source_hygiene.py` | NUL bytes + Trojan Source |
| `scripts/open-ui.ps1` | One command to sign in and open the browser |

### Modified — inspect before changing

- `apps/api/src/noctornal_api/projections.py` — **live-assertion filter**,
  `has_evidence`, `truncated`, evidence coverage. Everything downstream depends
  on `project()`.
- `apps/api/src/noctornal_api/http/static/app.js` — ~3,700 lines; Analysis,
  Triage and entity-resolution panels, resize handling.
- `apps/api/src/noctornal_api/security/auth.py` — recovery-code branch.
- `apps/api/src/noctornal_api/http/deps.py` — new composable `require_step_up`.

### Tests

`test_analytics.py` (maths vs published definitions), `test_analytics_pg.py`
(cache safety, clearance scoping), `test_provenance_pg.py` (E1–E3),
`test_recovery.py`, `test_egress.py`, `test_proposals_pg.py` (invariant 3),
`test_extraction.py` (mostly what must NOT be extracted), `test_capture_pg.py`,
`test_merges_pg.py`.

### Running it

```bash
powershell -ExecutionPolicy Bypass -File "scripts\launch.ps1"
```

```bash
powershell -ExecutionPolicy Bypass -File "scripts\open-ui.ps1"
```

Demo cases: **`OP-LATTICEWORK-26`** (15 actors, three crews, a sole bridge, a
redundant bridge pair, balanced + unbalanced triads — use this for the Analysis
tab) and `OP-NIGHTJAR-26` (a 7-node star; every Phase 3 metric is degenerate on
it). `OP-SCALE-*` is 400 synthetic nodes for the layout worker — delete freely.

```bash
.venv\Scripts\python -m pytest apps/api/tests packages/ontology/tests -q
```

Postgres legs gate on `DATABASE_URL`, evidence legs additionally on
`MINIO_ENDPOINT`, so the suite silently degrades to unit-only without the stack.
CI fails the run if anything skipped, for exactly that reason.
