# What is left on the roadmap

Regenerated 2026-07-25, end of session. `docs/09-roadmap.md` is the plan;
this is the honest delta between that plan and the build.

**State:** `main`, Alembic head `0042`, **1093 tests passing, 0 skipped**,
ruff clean, source hygiene clean. Nothing pushed (no remote configured).

> **Phase 7 has had its adversarial pass** (three lenses: access control,
> false attribution, cryptographic evidence), and every finding was put
> through a refutation round before being acted on. It produced **three
> CRITICAL/HIGH defects that a fully green 953-test suite did not see** —
> a forged PGP verdict, a 499× overstated tie weight, and a label defence
> that was absent on Russian-language forums. See decisions 59–60.

> **The most important files in the repo are
> [`docs/16-legal-and-external.md`](docs/16-legal-and-external.md) and
> [`docs/18-legal-review-pack.md`](docs/18-legal-review-pack.md).** Every
> phase is built. Four of them cannot lawfully be operated until somebody
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
| 2 — Sociogram | **95%** | ✅ | ✅ | ◐ | ✅ | WebSocket push; the UI polls. |
| 3 — Analytics | **85%** | ◐ | ✅ | ◐ | ✅ | CONCOR; charting metric history. Bipartite→one-mode landed for conversations only — actor×forum and actor×wallet still use two-mode presets, and `_mode_warning` still says so. |
| 4 — Collection | **75%** | ◐ | ✅ | ✅ | ✅ | XenForo/MyBB/Telegram adapters, embeddings, a scheduler process. UI landed 2026-07-25 (Feeds → Sources). All ten F15 service defects fixed at the service, with regressions. |
| 5 — Notification | **70%** | ◐ | ✅ | ◐ | ❌ | Jira, the integration admin surface, escalation of an unacknowledged priority-1, a worker. **Never reviewed.** |
| 6 — Tradecraft | **88%** | ◐ | ✅ | ✅ | ◐ | WebAuthn, timeline replay, the assumptions register, and a merge/reversal interface. Lifecycle, ACH and Report panes all landed 2026-07-26; entity merge is the one Phase 6 surface still API-only. |
| 7 — Comms | **85%** | ✅ | ✅ | ◐ | ✅ | **UI only.** The Comms pane covers the normalise preview and the contact-block parser — the two things an analyst gets wrong unaided. Bindings, PGP verification and co-participation are API-only. |
| 8 — Samples | **45%** | ◐ | ✅ | ❌ | ❌ | Fuzzy hashing (imphash/ssdeep/TLSH), YARA, prohibited-content screening, sandbox integration. Each absence is recorded on the sample row as a gap with a reason. **The one phase where 100% here would still mean "do not switch on" — see L1.** |
| 9 — Ingest | **90%** | ✅ | ✅ | ✅ | ✅ | The outbound credential vault with per-provider quota. Raw object storage landed 2026-07-25 (`rawstore.py`), so raw-before-parse is real rather than aspirational and re-parse works. Triage queue, dead letters and key admin all reached the UI. |

### Overall: **~83%** (was ~72% at the start of this session)

Unweighted mean across the ten phases. The +10 came from three things, in
descending order of how much they mattered:

- **Phase 9 from 55% to 90%**, mostly because raw-before-parse stopped
  being aspirational. `accept()` used to acknowledge a batch and drop the
  bytes; there was no listing endpoint, so a scored and prioritised queue
  had nothing reading it.
- **Phase 4 from 45% to 75%** and **Phase 6 from 55% to 80%** — UI, and
  the ten F15 service defects fixed at the service rather than compensated
  for at the router.
- Three new panes, which is most of the UI dimension for three phases.

Four things the number still hides:

1. **UI remains the largest single gap**, now concentrated rather than
   general: Phase 7 (comms — everything else about it is finished), the
   merge/ACH/report half of Phase 6, and Phase 8.
2. **Phases 5 and 8 have never had a hostile review.** Every review run on
   this project has found a real defect — four times a critical one, every
   time under a fully green suite. Treat an unreviewed phase as unknown
   rather than fine.
3. **Completion is not lawfulness.** A phase at 100% here may still be
   unlawful to operate. Phase 8 could reach 100% and must not be switched
   on until L1 is settled.
4. **Two retrospective items are open**, not future work: the dead-letter
   rows recorded before the redactor existed are still verbatim on disk
   (`scripts/redact_dead_letters.py --apply`), and any batch accepted
   before object storage was wired cannot be re-parsed. Both are docs/18
   Section D.

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

### 1. ~~An adversarial review pass over Phases 4 and 9~~ — done 2026-07-25

Both had one, and both produced real defects. The Phase 4/9 pass found ten
service-layer defects under a fully green suite, including victim PII
stored verbatim in an unlabelled table with no retention, an SSRF bypass
via `::ffff:127.0.0.1`, and a near-duplicate fingerprint that hashed a
document and its inverse identically. All ten are fixed at the service
with regressions (docs/17 F15).

**Phases 5 and 8 have still had none.** That is now the whole of this
line item.

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

### 2. UI for the phases that still have none

Ingest, collection and governance landed 2026-07-25 as the **Feeds** and
**Lifecycle** panes. What is left:

- **Comms (Phase 7)** — the Comms pane covers the normalise preview and the
  contact-block parser, which are the two things an analyst gets wrong
  unaided. Bindings, PGP verification and co-participation are API-only.
- **Entity merge (Phase 6)** — the one Phase 6 surface still without an
  interface. docs/01 calls merging "the operation most likely to quietly
  corrupt a case", so the control has to say what it will do *before* it
  does it, name which record loses, and keep every merge listed with a
  one-click reversal beside it. ACH and Report landed 2026-07-26.
- **Samples (Phase 8)** — last and carefully. Invariant 10: metadata may
  render, bytes may not, and no sandbox attribute may combine
  `allow-scripts` with `allow-same-origin`. **Do the adversarial pass
  first** — fixing a model defect after its UI is built costs the UI too.

Three things the first three panes taught, worth carrying into the next:

1. **`Promise.all` over endpoints with different permissions is wrong.**
   The first 403 rejects the lot, so a caller who holds four of five
   permissions sees an empty pane claiming they hold none. Load each
   section independently and say where it is refused.
2. **A permission error is not an empty state.** "Nothing here" and "you
   may not see what is here" are different facts and an analyst acts on
   them differently.
3. **Look at it rendered.** Two of the three defects in that work — the
   Promise.all one and an alert list padded with never-polled sources —
   were invisible to the test suite and obvious on screen in ten seconds.

### 3. ~~HTTP routers for Phases 4, 6 and 9~~ — done 2026-07-25

Every service now has a router. What is left on this axis is the UI.

### The sequence I would actually follow

Ordered so each step makes the next one cheaper, with the completion
gain each buys.

| # | Work | Buys | Why here |
|---|---|---|---|
| ~~1~~ | ~~Routers for 4, 6 and 9~~ | done 2026-07-25 | Every service has a router. |
| ~~2~~ | ~~Adversarial pass over 4 and 9~~ | done 2026-07-25 | Ten service defects, all now fixed at the service. |
| 1 | **Adversarial pass over 5 and 8** | +15% each (~**+3%**) | The only two phases never reviewed, and Phase 8 handles malware. Do it before its UI, not after: fixing a model defect once a UI is built costs the UI too. |
| 2 | **UI for 7 (finish), 6 (merge/ACH/reports), then 8** | ~**+6%** | Comms first — everything else about that phase is done. Samples **last** and carefully. |
| 3 | **Close the per-phase feature gaps** below | ~**+8%** | Adapters, WebAuthn, Jira, fuzzy hashing. Genuine feature work, and the part most exposed to the legal blockers. |
| 4 | **The two retrospective items** (docs/18 Section D) | 0% on this scale | Run the dead-letter redaction repair; decide what to do about batches accepted before object storage was wired. Neither scores; both are real. |
| 5 | **The deferred security items** | 0% on this scale | Scores nothing and matters anyway: session binding, RLS under a non-owner role, DNS-rebinding-proof SSRF protection, login timing. |

That reaches roughly **95%** with no phase below 85%. The last 5% is
WebSocket push, CONCOR, and the two-mode presets for actor×forum and
actor×wallet.

**None of it changes the four BLOCKING legal items.** A 95% build is still
one that must not be operated until L1–L4 are settled.

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
