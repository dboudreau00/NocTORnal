# What is left on the roadmap

Generated 2026-07-25, after the rate-limiting and four-eyes commits.
Companion to `docs/09-roadmap.md`, which is the plan; this is the honest
delta between that plan and the build.

**State:** `main`, 30 commits, Alembic head `0028`, 529 tests passing,
ruff clean, source hygiene clean. Nothing pushed (no remote configured).

---

## Scoreboard

| Phase | Status | What is actually missing |
|---|---|---|
| 0 — Foundation | ✅ **Done** | Nothing. CI runs four gates. No typecheck (deliberate — decision 42). |
| 1 — Graph core | ✅ **Done** | Nothing. |
| 2 — Sociogram | ✅ **Done** | WebSocket push for graph changes was never built; the UI polls. |
| 3 — Analytics | ✅ **Done** | Bipartite→one-mode, CONCOR/blockmodelling, charting the metric history. |
| 4 — Collection | 🟡 **~30%** | Everything that actually collects. The proposal/triage half is done. |
| 5 — Notification | 🟡 **~15%** | The egress gate exists. Nothing sends anything. |
| 6 — Tradecraft | 🟡 **~35%** | Merge + dual control done. ACH, reports, retention, WebAuthn, break-glass. |
| 7 — Comms channels | ⬜ **0%** | Decided (message-level capture) and unbuilt. |
| 8 — Sample handling | ⬜ **0%** | Was blocked; **unblocked by operator directive 2026-07-25**, building with a counsel-review disclaimer. |
| 9 — Ingest API | ⬜ **0%** | Concept only. Blocked on the stealer-log scope question. |

---

## The remaining work, in the order it should be done

### 1. Phase 5 — notification and integration

The egress gate (`egress.py`, decision 38) is built and tested. Everything
that would call it is not.

- [ ] **In-app notification centre.** The cheapest useful thing, and it
      unblocks two named gaps: docs/01 requires a **case-owner notification
      on merge**, and four-eyes approval currently gives an approver no way
      to learn a request is waiting for them. Both are silently missing.
- [ ] **SMTP** with digest, suppression, quiet hours, escalation. Mailpit is
      already in the compose stack and unused.
- [ ] **Outbound webhooks with HMAC.**
- [ ] **Jira**: outbound task creation, inbound status webhook, TLP ceiling.
- [ ] **Admin surface** for integration config and delivery logs.

Every one of these must call `can_egress()` before anything leaves. That is
invariant 8 and the gate already exists, so the failure mode to watch for is
an integration that grows its own copy — which is exactly what evidence
export had done before decision 38.

### 2. U2 — "why is this hidden"

An under-cleared analyst sees a smaller graph with no indication that
anything was withheld. That is a correctness problem, not a UX one: an
analyst who does not know a node is missing draws conclusions from a network
they believe is complete.

Needs care. A bare count of withheld elements is itself a weak side channel
("there are 4 RED nodes adjacent to this person"), so it probably has to be
a per-case setting — which now has a home, since `core."case"` gained its
first policy column in migration 0028.

### 3. Phase 6 remainder — tradecraft

- [ ] **ACH matrix and assumptions register.** Analysis of Competing
      Hypotheses. `core.hypothesis` already exists in the schema and is
      unused.
- [ ] **Report builder with TLP-aware redaction.** High value against
      decision 13's prosecution-grade posture, and a natural second caller
      for the egress gate.
- [ ] **Retention and purge with tombstones.** docs/08: the record of
      destruction survives the data. This is the first operation that will
      use four-eyes *unconditionally* — the mechanism from decision 44 is
      already registered for `evidence.purge`.
- [ ] **Break-glass.** `iam.break_glass` exists in the schema, unused.
- [ ] **WebAuthn.** Recovery codes landed; hardware keys did not.
- [ ] **Timeline scrubber and temporal replay.** The `as_of` scrubber
      exists on the sociogram; full replay does not.

### 4. Phase 8 — sample handling

**Was hard-blocked** on the absence of a prohibited-content policy
(decision 36). The operator directed on 2026-07-25 to build it anyway with a
disclaimer that counsel must review the deployment before it is used in any
absolute sense. Building it accordingly, with invariant 10 kept hard:

- [ ] Separate-origin sample service, download-only, **no rendering, no
      execution**
- [ ] Encrypted-at-rest storage keyed by SHA-256; EDR exclusions documented
- [ ] Quarantine → triage → RE queue, `MALWARE_ANALYST` as a distinct role
- [ ] Static triage: hashes, imphash, ssdeep, TLSH, YARA
- [ ] Fuzzy-hash clustering surfaced as graph edges
- [ ] Prohibited-content screening and the `REJECTED` path
- [ ] Detonation as an authorised, exposure-aware action

The disclaimer is not decoration. A store of attacker-supplied binaries will
eventually receive material whose possession alone is an offence, and the
handling rules differ between the two target jurisdictions (decision 13).
The code can be correct and the deployment still unlawful.

### 5. Phase 4 remainder — collection

Deliberately last among the buildable items. `docs/09` is explicit:

> the graph and assertion layer must work end to end before collection is
> switched on. Pointing a firehose at a half-built model produces a landfill.

- [ ] Adapter interface and scheduler with jitter and rate limiting (the
      limiter from decision 43 is per-request; per-source `max_rps` is a
      different shape)
- [ ] RSS adapter first — simplest, proves the pipeline
- [ ] Persona vault: envelope encryption, egress binding, status lifecycle
      (invariant 7 — credentials never leave the collector)
- [ ] XenForo, MyBB, Telegram MTProto adapters
- [ ] Document bucket: normalise, dedupe, version, index, embed
- [ ] Watch matching → watch hits
- [ ] Parser health checks and drift alerting (invariant 12 — nothing
      silently dropped; `ingest.dead_letter` exists and is unused)

### 6. Phases 7 and 9

- **Phase 7 (comms channels)** — decided as message-level capture
  (decision 35), zero built. Storage scales with traffic, every captured
  message is personal data inside the retention regime, and the Phase 5
  egress gate stops being advisory.
- **Phase 9 (ingest API)** — concept only, and **has its own open
  question**: are stealer logs in scope? If yes, the compartment and
  minimisation policy comes before any ingest code.

---

## Security items still deferred

Tracked here because they are not phase work and will otherwise be lost.

| Item | Why it matters | Notes |
|---|---|---|
| Session IP/UA binding | docs/05 asks for it; a stolen token is currently portable | Re-auth on mismatch, not silent kill |
| Non-owner DB role + RLS | The API connects as the table owner, so Postgres RLS is a no-op behind it | docs/05 wants RLS as a second line |
| Login timing equalisation | A missing account returns faster than a wrong password | Enumeration oracle |
| Compartment registry | Compartments are free-text; typos create silent no-access | |
| CI typecheck | No annotations to check against — a vacuously-passing mypy job is worse than none | decision 42 |
| Redis isolation | The limiter shares an instance running `allkeys-lru`, so meters are evictable under memory pressure | decision 43; deployment fix, not a code one |

---

## Known gaps in what IS built

Not roadmap items — things that are done but incomplete, and would surprise
someone reading the phase as "shipped".

- **The metric history endpoint exists and is tested. Nothing charts it.**
- **Two-mode presets warn rather than project.** Financial and Communication
  include `CONTROLS`/`TX_*` and `PARTICIPANT_IN`, so wallets, transactions
  and conversations become graph vertices. The analytics response warns
  (decision 33) rather than silently rewriting the presets, because that
  would change every Phase 2 number.
- **Per-case trust-decay default has no home.** The half-life is a request
  parameter stored on the projection. `core."case"` now has a policy column
  precedent (0028) but no column for this.
- **The triage queue has no notification.** An analyst finds out there is
  work by looking.
- **No WebSocket push.** Phase 2 listed it; the UI polls.

---

## Traps worth carrying forward

- **uvicorn runs WITHOUT `--reload`.** A new route 404s until restart. This
  has cost real time in three separate sessions.
- **TOTP cannot work on this host** — the clock is unsynchronised and sits
  in 2026. Sign in with `bootstrap.py session --email <you>`.
- **TOTP codes are single-use.** A test that logs in twice inside one
  30-second step fails on the replay guard, not on the code under test.
- **Test cleanup order matters.** `core.assertion` and `collect.proposal`
  both reference `collect.document`, and the deferred invariant-1 triggers
  fire at commit — so assertions and their elements must be deleted in ONE
  transaction. Anything that calls analytics also leaves
  `analytics.projection` rows that block the case delete.
- **A hidden browser tab clamps `setTimeout` to ~1s** and suspends
  `ResizeObserver`. Count messages and repaints, not wall time.
