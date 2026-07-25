# Session handoff — 2026-07-25 (second session)

Written so a fresh session can resume without re-deriving anything.

> **Read order for a new session:** this file, then `ROADMAP-REMAINING.md`
> (what is left, prioritised), then `CLAUDE.md` (the twelve invariants),
> then `docs/15-handoff.md` (the durable project record). `docs/00-decisions.md`
> now holds **49 numbered decisions**; 43–49 were taken in this session.

---

## 1. What this session did

Started from the previous handoff's priority list and worked down it, then
into Phases 6 and 8. Eight commits.

| Commit | What |
|---|---|
| `5359b52` | Rate limiting: GCRA in Redis, login metered by failures not attempts |
| `64f577f` | Four-eyes approval, dual control on merge as a per-case switch |
| `30ee5ed` | **Fix 12 defects an adversarial review found in the rate limiter** |
| `3665a78` | Phase 5: a notification centre whose email cannot carry the case file |
| `96af43c` | U2: tell an analyst their picture is incomplete |
| `ff3c9a0` | Phase 8: sample handling, block replaced by a refusal |
| `21e635c` | ACH: ranked by what a theory fails to explain |
| `78019df` | Report builder: structural redaction, mark follows contents |

**254 → 421 (previous session) → 673 tests.** Alembic `0027 → 0031`.

### The operator directives that shaped it

Two came mid-session and both are recorded as decisions:

1. **"With phase 8, build anyway and write a disclaimer that counsel is
   required to review the state before using in an absolute sense."**
   Decision 47 supersedes decision 36. The block became a *refusal with a
   named condition* rather than nothing: sample ingest is refused until an
   operator declares `NOCTORNAL_PROHIBITED_CONTENT_POLICY` and
   `NOCTORNAL_DESIGNATED_PERSON`. **That is a declaration the software
   records, not one it can verify.** The README warning block was rewritten
   to say so.
2. **"Export a what's-left-on-the-roadmap markdown."** → `ROADMAP-REMAINING.md`,
   regenerated at the end of the session.

---

## 2. The thing most worth knowing

**The adversarial review pass found a critical defect in code that had 484
passing tests over it.**

The blanket rate-limit ceiling was keyed only on the presented credential,
and nothing validates that a bearer token is a live session. A caller
rotating a random token per request minted a fresh empty meter every time.
Reproduced against the real app with the limit shrunk to 3: a fixed token
gave 27 refusals in 30 requests, a rotating one gave **zero**. Worse, the
bearer branch returned early and suppressed the address fallback, so sending
one garbage header made a caller *strictly less limited than sending none*.
The control inverted. It was also the only limiter on ~40 of 45 routes.

Eleven more followed, including: every IPv4-mapped address (`::ffff:a.b.c.d`)
sharing one bucket because they all have the `::/64`; the audit throttle
failing **open** during exactly the outage that makes every limit refuse; and
the async middleware doing blocking Redis I/O on the event loop, which
defeats the entire point of that limit failing open.

**Budget a review pass on anything substantial.** It has now found real bugs
on every single pass in this project's history, and the pattern holds:
reviewers told to *break* the thing find what reviewers told to *check* it do
not.

---

## 3. Current system state

| | |
|---|---|
| **Branch** | `main`, clean, nothing pushed (no remote) |
| **Migration head** | `0031`; each new migration round-trips against its predecessor |
| **Tests** | **673 passing**, 0 failing, 0 skipped with the stack up |
| **Lint** | `ruff check` clean; source hygiene clean (170 files) |
| **Python** | 3.13.14 |
| **New dependency** | `redis>=5.0` (in `apps/api/pyproject.toml`) |
| **CI** | now has a **redis service** — the Redis leg is env-gated and CI fails on skips |

### New environment variables

| Variable | Effect if unset |
|---|---|
| `REDIS_URL` | Rate limiting runs **per process** and warns loudly |
| `NOCTORNAL_TRUSTED_PROXY_HOPS` | `X-Forwarded-For` is ignored (correct default) |
| `NOCTORNAL_RATELIMIT=off` | Disables limiting entirely; warns on every start |
| `NOCTORNAL_PROHIBITED_CONTENT_POLICY` + `NOCTORNAL_DESIGNATED_PERSON` | **Sample ingest is refused** |
| `NOCTORNAL_SAMPLE_ORIGIN` | **Sample downloads are refused** (invariant 10) |
| `NOCTORNAL_BASE_URL`, `SMTP_*`, `NOCTORNAL_WEBHOOK_*` | Notification delivery is degraded or refused |

`scripts/launch.ps1` sets `REDIS_URL` to the compose default.

---

## 4. New modules

| Path | What |
|---|---|
| `ratelimit.py` / `ratelimit_redis.py` | Pure GCRA + the one Lua script |
| `http/limits.py` | Subject derivation, the dependency, the blanket middleware |
| `approvals.py` | Four-eyes: request → decide → consume, bound to a payload hash |
| `notifications.py` / `notify_events.py` / `transports.py` | The centre, the events, SMTP + webhooks |
| `samples.py` | Phase 8. Quarantine, triage, the origin refusal, the REJECTED path |
| `ach.py` | Analysis of Competing Hypotheses, scored |
| `reports.py` | Structural TLP redaction and the evidence register |
| `http/routers/` | `approvals.py`, `notifications.py`, `samples.py`, `ach.py`, `reports.py` |
| Migrations | `0028` approvals, `0029` notifications, `0030` withheld disclosure, `0031` lab |

---

## 5. Where to pick up

`ROADMAP-REMAINING.md` has the full list. The first three:

1. **Retention and purge with tombstones.** Highest value left, and the
   machinery exists — `evidence.purge` is already registered as an
   unconditional four-eyes operation (decision 44), so this is that
   mechanism's first real user. Watch the COMPLIANCE-mode object lock: MinIO
   will refuse to delete before `retain_until` even for the API's own
   credentials, so purge has to reason about the lock rather than assume.
2. **Break-glass.** `iam.break_glass` has existed since Phase 0 with nothing
   writing it, and `BREAK_GLASS_INVOKED` is already a registered priority-1
   notification kind that overrides quiet hours — so the alert docs/05 asks
   for now has somewhere to go.
3. **UI for ACH, reports and samples.** All three have tested endpoints and
   no interface. Samples last and carefully: invariant 10 says metadata may
   render and bytes may not.

---

## 6. Traps

- **uvicorn runs WITHOUT `--reload`.** A new route 404s until restart. Four
  sessions running.
- **TOTP cannot work on this host** (unsynchronised clock, in 2026). Sign in
  with `.venv\Scripts\python scripts\bootstrap.py session --email <you>`.
- **TOTP codes are single-use** — a test that logs in twice inside one
  30-second step fails on the replay guard, not on the code under test.
- **The TLP floor trigger forbids an element BELOW its case.** A fixture with
  a GREEN node in an AMBER case fails at the database.
- **Test cleanup order keeps growing.** Anything calling analytics leaves
  `analytics.projection` rows; anything merging or approving leaves
  notifications; both block the case delete. Assertions and their elements
  must be deleted in ONE transaction (deferred invariant-1 triggers).
- **Do not run the suite while background agents are running it.** The e2e
  cleanup deletes by email pattern and two runs delete each other's users;
  the failures look real and are not.
- **A hidden browser tab clamps `setTimeout` to ~1s** and suspends
  `ResizeObserver`.

## 7. Running it

```bash
powershell -ExecutionPolicy Bypass -File "scripts\launch.ps1"
```

```bash
powershell -ExecutionPolicy Bypass -File "scripts\open-ui.ps1"
```

```bash
.venv\Scripts\python -m pytest apps/api/tests packages/ontology/tests -q
```

Postgres legs gate on `DATABASE_URL`, evidence on `MINIO_ENDPOINT`, the
limiter's Lua on `REDIS_URL`. CI fails the run if anything skipped.
