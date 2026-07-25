# Session handoff — 2026-07-25

Written so a fresh session can resume without re-deriving anything.

> **Read order:** this file → `docs/16-legal-and-external.md` (**every
> external/legal dependency, and the only file that can stop a deployment**)
> → `ROADMAP-REMAINING.md` → `CLAUDE.md` (the twelve invariants) →
> `docs/00-decisions.md` (54 numbered decisions).

---

## 1. Context & Objective

**NocTORnal** is a HUMINT / social-network-analysis platform for cybercrime
investigation: analysts build a graph of criminal actors, personas, groups
and the trust between them, every element traceable to graded evidence with
a chain of custody. Comparable to Maltego, i2 and SL Crimewall, with
UCINET-grade SNA maths. Python 3.13 / FastAPI / Postgres 16, plain-HTML
analyst UI under a strict CSP with no build step.

**This session's objective**, as given across several messages:

1. Resume from the previous handoff and work its priority list.
2. *"With phase 8, build anyway and write a disclaimer to note counsel is
   required to review the state before using in an absolute sense."*
3. *"Export a what's-left-on-the-roadmap markdown."*
4. *"Continue with the phases until each of them are built with nuances
   recorded like 'remove X without legal counsel, and determination'
   recorded in notes. Be explicit about what needs to be confirmed with
   external sources. Complete all phases to the best of your ability,
   including the collection, comms channels, sample handling — and yes,
   stealer logs are in scope for 9."*

**All nine phases now have an implementation.** The nuance-recording ask is
answered by `docs/16-legal-and-external.md`, which is the deliverable most
worth reading first.

---

## 2. Completed Work

### Before this session

Phases 0–3 complete: Alembic-owned schema (0001–0027), Argon2id + TOTP auth,
the five-part access gate as one `evaluate()`, the assertion layer enforced
by deferred DB triggers, WORM evidence with a hash-chained custody ledger,
the Phase 2 sociogram, Phase 3 analytics (betweenness, Burt, Leiden, key
player), manual capture + triage, reversible entity merge, CI. **421 tests.**

### Built this session — 16 commits, 421 → 807 tests, Alembic 0027 → 0034

| Commit | What | Migration |
|---|---|---|
| `5359b52` | Rate limiting: GCRA in Redis, login metered by failures | — |
| `64f577f` | Four-eyes approval + dual control on merge | 0028 |
| `30ee5ed` | **Fix 12 defects an adversarial review found** | — |
| `3665a78` | Phase 5: notification centre, SMTP, HMAC webhooks | 0029 |
| `96af43c` | U2: tell an analyst their picture is incomplete | 0030 |
| `ff3c9a0` | Phase 8: sample handling | 0031 |
| `21e635c` | ACH matrix | — |
| `78019df` | Report builder with TLP redaction | — |
| `4cc0b52` | docs: roadmap + handoff | — |
| `27724cf` | Phase 6: retention tombstones + break-glass | 0032 |
| `1e34396` | Phase 9: ingest + stealer logs | 0033 |
| `e56221e` | Phase 4: collection, adapters, persona vault | — |
| `f9109e6` | Phase 7: comms channels | 0034 |

### Bugs found that were NOT in the brief

1. **CRITICAL — the blanket rate limit was not a limit.** Keyed only on the
   presented credential with no liveness check, so rotating a Bearer token
   escaped it entirely: with the limit at 3, a fixed token gave 27 refusals
   in 30 requests and a rotating one gave **zero**. Worse, a garbage token
   suppressed the address fallback, so sending one extra header made a
   caller *strictly less limited than sending none*. It was the only limiter
   on ~40 of 45 routes.
2. **Every IPv4-mapped address shared one bucket** (`::ffff:a.b.c.d` all
   have the `::/64`). On a dual-stack listener the first person to mistype a
   password would have locked out the internet.
3. **The audit throttle failed open** during exactly the outage that makes
   every limit refuse — the outage would have authored the flood.
4. **`legal_hold` was on nothing.** docs/08 says it "overrides all deletion,
   everywhere"; `core."case"` never had the column and evidence had no
   reason field, so the rule could not be expressed at all.
5. **A stealer-log compartment CHECK never fired** on the empty array it
   existed to catch: `array_length('{}',1)` is NULL, and `NULL >= 1` is NULL
   rather than false.
6. **A never-polled collection source waited a full interval** before its
   first poll — a newly-added source would sit idle and look broken.
7. The e2e cleanup fixture never deleted analytics projections, so any test
   calling analytics blocked its own case delete.

---

## 3. Current System State

| | |
|---|---|
| **Branch** | `main`, clean, **nothing pushed** (no remote configured) |
| **Migration head** | `0034`; each new migration round-trips against its predecessor |
| **Tests** | **807 passing**, 0 failing, 0 skipped with the stack up |
| **Lint** | `ruff check` clean; source hygiene clean (186 files) |
| **Python** | 3.13.14 |
| **Stack** | Docker Compose: postgres, redis, nats, minio, openfga, mailhog |

### Key architectural decisions (43–54 in `docs/00-decisions.md`)

- **43/45 — Rate limiting is GCRA in Redis, and fail-open vs fail-closed is
  answered PER LIMIT.** Cost-bearing limits fail closed (503); only the
  blanket ceiling fails open, so a Redis restart degrades features instead
  of bricking an investigation tool. Login is metered **twice**: a generous
  attempt limit (a NAT'd unit signs on from one address) and a tight
  *failure* limit that only a guesser moves.
- **44 — Four-eyes approval binds to a payload hash.** Under dual control
  the merge endpoint reads only `approval_request_id` and executes the
  parameters recorded on it — there is nothing to substitute. Merge defaults
  to OFF because a merge here is a reversible ledger.
- **46 — Notification content is split into three fields by where each may
  appear.** `Outgoing` does not carry the body at all, so the email renderer
  *cannot* leak it.
- **47 — Phase 8 built; the block became a refusal with a named condition.**
  Nothing ingests until an operator declares a policy reference and a
  designated person. **That is a declaration the software records, not one
  it can verify.**
- **49 — Report redaction is structural, and the document's mark follows its
  contents.** `target_tlp` is a ceiling on inclusion, not the mark.
- **50 — Purge writes a tombstone that outlives the data**, and records
  `storage_outcome` because COMPLIANCE-mode object lock can refuse a delete
  *even to satisfy a deletion order*.
- **52 — Stealer logs: free-text PII search is impossible, not forbidden.**
  No tsvector, no trigram index, ciphertext values — there is nothing to run
  a LIKE against.
- **54 — Comms: the durable-selector mapping is the product.** Tox → first
  64 hex; Telegram → numeric ID, never `@username`; SimpleX → no identifier,
  said out loud.

---

## 4. Immediate Next Steps & Pending Work

### 🔴 Blockers — these are legal, not technical

**Read `docs/16-legal-and-external.md`.** Four BLOCKING items; the build runs
without them and **should not be operated** until they are settled:

- **L1** — prohibited-content policy for the sample store. In particular:
  the `REJECTED` path currently **destroys** the bytes, which is the wrong
  answer in a jurisdiction requiring preservation. `reject(purge_bytes=False)`
  exists and nothing selects it automatically.
- **L2** — the lawful basis for holding stealer-log data about thousands of
  uninvolved people, victim-notification obligations, and the real retention
  period (90 days is a placeholder).
- **L3** — authority to operate a covert persona per jurisdiction, and
  whether passive and active collection are separately authorised.
- **L4** — interception law and consent for message capture.

Plus **10 items to confirm against an external source** (C1–C10), including
evidence-authenticity standards, MinIO COMPLIANCE semantics on your actual
object store, and the platform durable-identifier mappings, which change.

### Prioritised engineering work

1. **UI for the new phases.** ACH, reports, samples, ingest, comms and
   governance all have tested services and **no interface**. Samples last
   and carefully — invariant 10 says metadata may render and bytes may not.
2. **HTTP routers for Phases 4, 6, 7, 9.** Services and tests exist;
   `approvals`, `notifications`, `samples`, `ach`, `reports` have routers,
   the rest do not.
3. **A second adversarial review pass**, over Phases 4/7/9. The first one
   found a critical defect under 484 green tests; these phases have had none.
4. **WebAuthn**, and the deferred security items (session IP/UA binding,
   non-owner DB role + RLS, login timing equalisation).
5. **Real SSRF protection.** `collection.fetch()` has a floor — non-HTTP
   schemes and private literals — and DNS rebinding is not addressed.
6. **Fuzzy hashing for Phase 8** (ssdeep/TLSH/imphash) and YARA. Each
   absence is already recorded on the sample row as a gap with a reason.

### Open questions

- **Ingest key holders** — internal only or external partners? Changes the
  support and abuse model (docs/16 D6).
- **Expected ingest volume.** Above ~1M records/day the bucket needs a
  different storage tier.
- **Which sandbox vendors count as "private"** for detonation exposure.
- **Who is the security officer?** Break-glass *refuses to grant* if no
  active user holds `SECURITY_OFFICER` — deliberately.

---

## 5. Relevant File Paths & References

### New this session

| Path | What |
|---|---|
| `docs/16-legal-and-external.md` | **The register. Read first.** |
| `apps/api/src/noctornal_api/ratelimit.py`, `ratelimit_redis.py` | Pure GCRA + one Lua script |
| `apps/api/src/noctornal_api/http/limits.py` | Subject derivation, dependency, middleware |
| `apps/api/src/noctornal_api/approvals.py` | Four-eyes, bound to a payload hash |
| `apps/api/src/noctornal_api/notifications.py`, `notify_events.py`, `transports.py` | Phase 5 |
| `apps/api/src/noctornal_api/samples.py` | Phase 8 |
| `apps/api/src/noctornal_api/ach.py` | ACH, ranked by inconsistency |
| `apps/api/src/noctornal_api/reports.py` | Structural TLP redaction |
| `apps/api/src/noctornal_api/retention.py`, `break_glass.py` | Phase 6 |
| `apps/api/src/noctornal_api/ingest.py` | Phase 9 + stealer logs |
| `apps/api/src/noctornal_api/collection.py` | Phase 4 |
| `apps/api/src/noctornal_api/comms.py` | Phase 7 |
| `db/migrations/versions/0028`–`0034` | approvals, notify, withheld, lab, retention, ingest, comms |

### Modified — inspect before changing

- `apps/api/src/noctornal_api/projections.py` — `withheld()` was added; every
  metric depends on `project()`.
- `apps/api/src/noctornal_api/merges.py`, `approvals.py` — both now raise
  notifications inside their transactions.
- `apps/api/src/noctornal_api/http/app.py` — routers and middleware ORDER
  (the limiter must register *before* the security headers).

### New environment variables

| Variable | Effect if unset |
|---|---|
| `REDIS_URL` | Rate limiting runs **per process** and warns |
| `NOCTORNAL_INGEST_PEPPER` | **Ingest keys cannot be issued or verified** |
| `NOCTORNAL_PROHIBITED_CONTENT_POLICY` + `NOCTORNAL_DESIGNATED_PERSON` | **Sample ingest is refused (451)** |
| `NOCTORNAL_SAMPLE_ORIGIN` | **Sample downloads are refused** (invariant 10) |
| `NOCTORNAL_TRUSTED_PROXY_HOPS` | `X-Forwarded-For` ignored (correct default) |
| `NOCTORNAL_RATELIMIT=off` | Disables limiting; warns every start |
| `SMTP_*`, `NOCTORNAL_BASE_URL`, `NOCTORNAL_WEBHOOK_*` | Notification delivery degraded |

### Traps that cost real time

- **uvicorn runs WITHOUT `--reload`.** A new route 404s until restart. Five
  sessions running.
- **TOTP cannot work on this host** (unsynchronised clock, in 2026). Sign in
  with `.venv\Scripts\python scripts\bootstrap.py session --email <you>`.
- **TOTP codes are single-use** — two logins inside one 30-second step fail
  on the replay guard, not on the code under test.
- **Constraints tie fields together and fire on UPDATE.** A case cannot be
  created already expired (`case_retention_sane` ties retention to
  `created_at`), a break-glass grant cannot be aged without staying ≤8h, and
  an ingest key cannot expire before it was issued. Age the *pair*.
- **`array_length('{}', 1)` is NULL, not 0.** Any `>= 1` check on an array
  needs `coalesce`, or it silently passes on the empty case.
- **A partial unique index needs its predicate restated in `ON CONFLICT`.**
- **Retention rules are GLOBAL**, so a test that confirms one leaks into
  every later test.
- **Do not run the suite while background agents run theirs** — the e2e
  cleanup deletes by email pattern and concurrent runs delete each other's
  fixtures. The failures look real and are not.

### Running it

```bash
powershell -ExecutionPolicy Bypass -File "scripts\launch.ps1"
```

```bash
.venv\Scripts\python -m pytest apps/api/tests packages/ontology/tests -q
```

Postgres legs gate on `DATABASE_URL`, evidence on `MINIO_ENDPOINT`, the
limiter's Lua on `REDIS_URL`. **CI fails the run if anything skipped.**
