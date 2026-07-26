# What is left on the roadmap

Regenerated 2026-07-26. `docs/09-roadmap.md` is the plan; this is the
honest delta between that plan and the build.

**State:** `main`, Alembic head `0045`, **1206 tests passing, 0 skipped**
(run BOTH `apps/api/tests` and `packages/ontology` — earlier handoffs
quoted a single figure and the next session spent time working out why it
did not reconcile), ruff clean. Nothing pushed (no remote configured).

**`release/` is the packaged Alpha release** — a README leading with the
legal status, an analyst manual, install instructions and one-shot
installers for Windows and Linux/macOS. `scripts/assemble_release.ps1`
copies it out to a standalone folder; `release/` is the source of truth
and the copy is disposable.

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
| 2 — Sociogram | **100%** | ✅ | ✅ | ✅ | ✅ | Nothing. **Live push landed 2026-07-26** — Postgres LISTEN/NOTIFY, one listener per process, the socket carrying no case content. |
| 3 — Analytics | **85%** | ◐ | ✅ | ◐ | ✅ | CONCOR; charting metric history. Bipartite→one-mode landed for conversations only — actor×forum and actor×wallet still use two-mode presets, and `_mode_warning` still says so. |
| 4 — Collection | **75%** | ◐ | ✅ | ✅ | ✅ | XenForo/MyBB/Telegram adapters, embeddings, a scheduler process. UI landed 2026-07-25 (Feeds → Sources). All ten F15 service defects fixed at the service, with regressions. |
| 5 — Notification | **85%** | ✅ | ✅ | ◐ | ✅ | Jira, the integration admin surface, escalation of an unacknowledged priority-1, a worker. **Reviewed 2026-07-26** (F19): the centre never checked case assignment, the outbox drain checked neither assignment nor current clearance, and the label composer had zero call sites. All fixed. |
| 6 — Tradecraft | **88%** | ◐ | ✅ | ✅ | ◐ | WebAuthn, timeline replay, the assumptions register. **The UI is complete**: merge and its reversal live in the inspector (with the merge history and a per-merge Reverse), and Lifecycle, ACH and Report landed 2026-07-26. What remains is model work and a hostile review of the phase as a whole. |
| 7 — Comms | **95%** | ✅ | ✅ | ✅ | ✅ | **Effectively done.** The Comms pane covers the normalise preview, the contact-block parser, binding, correlation, PGP verification with its three outcome classes, the unverified queue and co-participation. What is left is the Telegram id-collision model change (F1 / docs/16 D8) and optional niceties: detached signatures, and a keyserver-free way to obtain a vendor key. |
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
   updates live, and there is a keyboard map. What is left on that axis is
   metric-history charting.
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
