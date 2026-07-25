# What is left on the roadmap

Regenerated 2026-07-25, end of session. Companion to `docs/09-roadmap.md`,
which is the plan; this is the honest delta between that plan and the build.

**State:** `main`, 8 commits this session, Alembic head `0031`,
**673 tests passing**, ruff clean, source hygiene clean, migrations
round-trip. Nothing pushed (no remote configured).

---

## Scoreboard

| Phase | Status | What is actually missing |
|---|---|---|
| 0 — Foundation | ✅ **Done** | Nothing. No typecheck, deliberately (decision 42). |
| 1 — Graph core | ✅ **Done** | Nothing. |
| 2 — Sociogram | ✅ **Done** | WebSocket push was never built; the UI polls. |
| 3 — Analytics | ✅ **Done** | Bipartite→one-mode, CONCOR, charting the metric history. |
| 4 — Collection | 🟡 **~30%** | Everything that actually collects. Proposals and triage are done. |
| 5 — Notification | 🟢 **~75%** | Jira, the integration admin surface, escalation, a worker. |
| 6 — Tradecraft | 🟢 **~65%** | Retention/purge, break-glass, WebAuthn, timeline replay. |
| 7 — Comms channels | ⬜ **0%** | Decided (message-level capture, decision 35) and unbuilt. |
| 8 — Sample handling | 🟢 **~70%** | Built (decision 47). Missing: fuzzy hashing, YARA, screening, sandbox. |
| 9 — Ingest API | ⬜ **0%** | Concept only. Blocked on the stealer-log scope question. |

### Shipped this session

| | Decision | Migration |
|---|---|---|
| Rate limiting, GCRA in Redis | 43, 45 | — |
| Four-eyes approval + dual control on merge | 44 | 0028 |
| Notification centre, SMTP, webhooks | 46 | 0029 |
| U2 "why is this hidden" | — | 0030 |
| Phase 8 sample handling | 47 | 0031 |
| ACH matrix | 48 | — |
| Report builder with TLP redaction | 49 | — |

An adversarial review of the rate limiter (31 agents, 27 findings, 15
refuted) found **12 real defects including one critical**: the blanket
ceiling was keyed only on the presented credential, so rotating a Bearer
token escaped it entirely — and sending a garbage token was *cheaper* than
sending none. All 12 are fixed with a regression test each (decision 45).
Budget for a review pass on anything substantial; it has now found real bugs
on every single pass in this project's history.

---

## The remaining work, in the order it should be done

### 1. Retention and purge with tombstones — Phase 6

The highest-value thing left, and the machinery is already there.

- [ ] Scheduled purge on `retention_until`, with `legal_hold` overriding
      everything.
- [ ] Out-of-schedule purge behind four-eyes. **`evidence.purge` is already
      registered as an unconditional dual-control operation** (decision 44),
      so this is the first real user of that mechanism.
- [ ] Tombstones: docs/08 requires the record of destruction to survive the
      data — what was destroyed, under what authority, by whom.
- [ ] Documents supporting an accepted assertion pinned past source
      retention. Otherwise you delete the evidence and leave the conclusion,
      which is the worst possible outcome.

**Watch out:** evidence is in COMPLIANCE-mode object lock, so MinIO will
refuse to delete before `retain_until` *even for the API's own credentials*.
That is correct and it means purge has to reason about the lock rather than
assume a delete succeeds.

### 2. Break-glass — Phase 6

`iam.break_glass` has existed since Phase 0 with nothing writing it. docs/05:
available, loud and short — mandatory justification, hard expiry, immediate
alert to the security officer, mandatory post-hoc review. **The alert now has
somewhere to go**: `BREAK_GLASS_INVOKED` is already a registered priority-1
notification kind that overrides quiet hours.

### 3. Phase 5 remainder

- [ ] Jira: outbound task creation, inbound status webhook, TLP ceiling. The
      HMAC-signed webhook transport it would specialise already exists.
- [ ] Admin surface for integration config and delivery logs. The
      `notify.delivery` ledger records every refusal and suppression with a
      reason; nothing renders it.
- [ ] Escalation of an unacknowledged priority-1 notification.
- [ ] A worker. `POST /notifications/dispatch` is called by an operator or a
      cron entry today (decision 46, following decision 30).

### 4. Phase 8 remainder

- [ ] imphash, ssdeep, TLSH — each needs a dependency, and ssdeep needs a C
      toolchain on Windows. Every absence is already recorded on the sample
      row as a gap with a reason.
- [ ] YARA against a rule corpus — docs/11 calls it the highest-value single
      component.
- [ ] Fuzzy-hash clustering as graph edges. Blocked on the hashes above.
- [ ] Archive expansion **with depth and expansion-ratio caps**. Uncapped is
      a zip bomb waiting for someone to send one.
- [ ] Automated prohibited-content screening. Needs an authorised hash set,
      which is a legal question before it is a technical one.
- [ ] Sandbox integration (CAPEv2 / Triage / Joe). The authorisation record
      and its constraint exist; nothing submits.

### 5. Phase 6 remainder

- [ ] WebAuthn. Recovery codes landed in Phase 3; hardware keys did not.
- [ ] Timeline scrubber and full temporal replay. The `as_of` scrubber
      exists on the sociogram.
- [ ] Assumptions register alongside ACH.
- [ ] Backup and restore rehearsal.

### 6. Phase 4 — collection

Still deliberately last among the buildable items. `docs/09`: the graph and
assertion layer must work end to end before collection is switched on,
because a firehose into a half-built model produces a landfill.

Adapter interface and scheduler, RSS first, persona vault with envelope
encryption and egress binding, XenForo/MyBB/Telegram adapters, the document
bucket, watch matching, parser health checks. `ingest.dead_letter` exists and
is unused.

### 7. Phases 7 and 9

- **Phase 7** — decided as message-level capture (decision 35), zero built.
- **Phase 9** — concept only, and has its own open question: are stealer
  logs in scope? If yes, the compartment and minimisation policy comes
  before any ingest code.

---

## Security items still deferred

| Item | Why it matters |
|---|---|
| Session IP/UA binding | A stolen token is currently portable |
| Non-owner DB role + RLS | The API connects as the table owner, so Postgres RLS is a no-op behind it |
| Login timing equalisation | A missing account returns faster than a wrong password |
| SSRF protection | Needed before watch targets exist (Phase 4) |
| Compartment registry | Compartments are free-text; a typo creates silent no-access |
| CI typecheck | No annotations to check against; a vacuously-passing mypy job is worse than none |
| Redis isolation | The limiter shares an instance running `allkeys-lru`, so meters are evictable |
| Sample origin split | `NOCTORNAL_SAMPLE_ORIGIN` is enforced at runtime, but the *deployment* has to actually provide a second origin |

---

## Known gaps in what IS built

- **The metric history endpoint exists and is tested. Nothing charts it.**
- **Two-mode presets warn rather than project** (decision 33).
- **Per-case trust-decay default has no home.** `core."case"` now has three
  policy columns (`dual_control_merge`, `withheld_disclosure`) so the
  precedent exists.
- **No WebSocket push.** Phase 2 listed it; the UI polls.
- **The ACH matrix has no UI.** Endpoints exist and are tested.
- **The report builder has no UI.** Same.
- **Sample handling has no UI** — deliberately last, because invariant 10
  says metadata may render and bytes may not, and that distinction is worth
  building carefully rather than quickly.

---

## Traps worth carrying forward

- **uvicorn runs WITHOUT `--reload`.** A new route 404s until restart. This
  has now cost time in four separate sessions.
- **TOTP cannot work on this host** — the clock is unsynchronised and sits
  in 2026. Sign in with `bootstrap.py session --email <you>`.
- **TOTP codes are single-use.** A test that logs in twice inside one
  30-second step fails on the replay guard, not on the code under test.
- **The TLP floor trigger forbids an element BELOW its case**, so a test
  fixture with a GREEN node in an AMBER case fails at the database.
- **Test cleanup order matters and keeps growing.** Anything that calls
  analytics leaves `analytics.projection` rows; anything that merges or
  approves leaves notifications; both block the case delete. Assertions and
  their elements must go in ONE transaction, because the deferred
  invariant-1 triggers fire at commit.
- **Running the suite while background agents are also running it** produces
  failures that are pure interference — the e2e cleanup deletes by email
  pattern and two runs delete each other's users.
- **A hidden browser tab clamps `setTimeout` to ~1s** and suspends
  `ResizeObserver`. Count messages and repaints, not wall time.
