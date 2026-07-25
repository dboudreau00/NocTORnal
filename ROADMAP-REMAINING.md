# What is left on the roadmap

Regenerated 2026-07-25, end of session. `docs/09-roadmap.md` is the plan;
this is the honest delta between that plan and the build.

**State:** `main`, Alembic head `0036`, **953 tests passing**, ruff clean,
source hygiene clean, migrations round-trip. Nothing pushed (no remote
configured).

> **The most important file in the repo is now
> [`docs/16-legal-and-external.md`](docs/16-legal-and-external.md).** Every
> phase is built. Four of them cannot lawfully be operated until somebody
> outside this codebase makes a decision, and that file is the list.

---

## Scoreboard

| Phase | Status | What is actually missing |
|---|---|---|
| 0 — Foundation | ✅ **Done** | Nothing. No typecheck, deliberately (decision 42). |
| 1 — Graph core | ✅ **Done** | Nothing. |
| 2 — Sociogram | ✅ **Done** | WebSocket push; the UI polls. |
| 3 — Analytics | ✅ **Done** | CONCOR, charting metric history. Bipartite→one-mode landed for conversations (see Phase 7); actor×forum and actor×wallet still use the two-mode presets, and `_mode_warning` still says so. |
| 4 — Collection | 🟢 **~70%** | XenForo/MyBB/Telegram adapters, embeddings, a scheduler process. |
| 5 — Notification | 🟢 **~75%** | Jira, integration admin surface, escalation, a worker. |
| 6 — Tradecraft | 🟢 **~85%** | WebAuthn, timeline replay, assumptions register. |
| 7 — Comms | 🟢 **~90%** | UI. The contact-block parser, PGP verification, co-participation and the HTTP router all landed 2026-07-25. |
| 8 — Samples | 🟢 **~70%** | Fuzzy hashing, YARA, screening, sandbox integration. |
| 9 — Ingest | 🟢 **~80%** | The HTTP 202 endpoint wiring, outbound credential vault. |

**Every phase has an implementation and a test suite.** None has a UI beyond
Phases 1–3 and the notification centre.

---

## 🔴 Before anything else: the legal register

`docs/16-legal-and-external.md` holds **4 BLOCKING items, 7 determinations
and 10 things to confirm externally.** The four blockers, compressed:

| | What | Why it blocks |
|---|---|---|
| **L1** | Prohibited-content policy for samples | The build refuses ingest until a policy reference and a designated person are declared — but **that is a declaration it records, not one it can verify**. Also: `REJECTED` currently *destroys* the bytes, which is wrong in a jurisdiction requiring preservation. |
| **L2** | Stealer-log lawful basis, victim notification, real retention | Holding data about thousands of uninvolved people. 90 days is a placeholder. |
| **L3** | Persona operation authority | The software will drive an account into a forum. Whether you may is not a software question. |
| **L4** | Interception law and consent | Message capture. `provenance_class` records *which* kind; the authority is external. |

The ten **CONFIRM EXTERNALLY** items include evidence-authenticity standards
(reasoned from the rule text, not from a practitioner), MinIO COMPLIANCE
semantics on your actual object store, and the platform durable-identifier
mappings — which change, and where a stale mapping produces confident false
attribution.

---

## Prioritised engineering work

### 1. A second adversarial review pass

Phases 4, 7 and 9 have had none. The first pass in this project found a
**critical** defect under 484 green tests — the blanket rate limit was keyed
on a value the caller controls, so rotating a token escaped it entirely, and
sending a garbage token was *cheaper* than sending none. That pattern has
held on every review in this project's history.

### 2. UI for the new phases

ACH, reports, samples, ingest, comms and governance all have tested services
and **no interface**. Samples last and carefully: invariant 10 says metadata
may render and bytes may not, and no sandbox attribute may combine
`allow-scripts` with `allow-same-origin`.

### 3. HTTP routers for Phases 4, 6 and 9

Services and tests exist. `approvals`, `notifications`, `samples`, `ach`,
`reports` and now `comms` have routers; retention, break-glass, collection
and ingest do not.

### 4. The remaining per-phase work

- **Phase 4** — XenForo, MyBB, Telegram MTProto adapters (each blocked on
  L3 as much as on code); document embeddings; a scheduler process.
- **Phase 5** — Jira, the integration admin surface (the `notify.delivery`
  ledger records every refusal with a reason and nothing renders it),
  escalation of an unacknowledged priority-1, a worker.
- **Phase 6** — WebAuthn, timeline replay, the assumptions register.
- **Phase 7** — done except the UI. What remains is genuinely optional:
  loose matching of a differently-formatted identifier inside a signed
  payload (deliberately not done — a false confirmation costs far more
  than a second look), detached-signature support alongside clearsigned,
  and a keyserver-free way to obtain a vendor's public key.
- **Phase 8** — imphash/ssdeep/TLSH (each a dependency; ssdeep needs a C
  toolchain on Windows), YARA, capped archive expansion, sandbox
  integration. Every absence is already recorded on the sample row as a gap
  with a reason.
- **Phase 9** — the HTTP 202 endpoint wiring, and the outbound credential
  vault with per-provider quota and exposure levels.

### 5. Security items still deferred

| Item | Note |
|---|---|
| Real SSRF protection | `collection.fetch()` has a floor; DNS rebinding is not addressed |
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
