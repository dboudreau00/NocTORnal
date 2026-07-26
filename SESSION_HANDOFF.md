# Session handoff — 2026-07-25 (Phase 7 completion)

Written so a fresh session can resume without re-deriving anything.

> **Read order:** this file → `docs/16-legal-and-external.md` (**every
> external/legal dependency, and the only file that can stop a
> deployment**) → `docs/17-flagged-for-review.md` (**everything built on a
> judgement somebody should confirm, and the rows already recorded that
> should not be trusted**) → `ROADMAP-REMAINING.md` → `CLAUDE.md` (the
> twelve invariants) → `docs/00-decisions.md` (60 numbered decisions).

---

## 1. Context & Objective

**NocTORnal** is a HUMINT / social-network-analysis platform for cybercrime
investigation: analysts build a graph of criminal actors, personas, groups
and the trust between them, every element traceable to graded evidence with
a chain of custody. Comparable to Maltego, i2 and SL Crimewall, with
UCINET-grade SNA maths. Python 3.13 / FastAPI / Postgres 16, plain-HTML
analyst UI under a strict CSP with no build step.

The previous session brought all nine phases to a first implementation.
**This session was asked to continue from Phase 7 onward**, and Phase 7 is
now complete except for its UI.

---

## 2. What was built this session

Eight commits on `main`, **807 → 1012 tests**, Alembic **0034 → 0039**.

| Commit | What |
|---|---|
| `74a055d` | Contact-block parser + the normaliser divergence it exposed (0035, 0036) |
| `ea4fbfa` | PGP signature verification, delegated to gpg |
| `25cc698` | Co-participation projection + the Phase 7 HTTP router |
| `565ea7f` | Decisions 55–58, legal register C11–C13, roadmap |
| `12ff904` | **CRITICAL: forged `VALIDSIG` via a crafted user ID** (0037) |
| `8595602` | The rest of the review: 10 further defects |
| `c9a0678` | The last five flagged items, README disclaimer, `docs/17` |
| `413efbd` | Routers for Phases 4, 6 and 9 (30 endpoints) + migrations 0038/0039 |

### The contact-block parser (docs/10's "highest-value extraction target")

The design brief is one sentence of docs/10: *"Attributing the escrow's
Jabber to the vendor is a serious, and easy, error."* So the parser
**refuses more than it resolves**. A labelled line resolves by its label; an
unlabelled one only on an unambiguous shape. Bare 40-hex does not resolve
(SHA-1 is identical), 64-hex does not (Tox pubkey, SHA-256 and OMEMO all
match), `local@domain` does not (a JID and an email are the same shape).
Refusals are kept as `UNPARSED` **with the reason** — invariant 12.

Four defences against the escrow error, deliberately independent: the role
label, the inline disclaimer, the GLOBAL stoplist, and shared-service
detection over **distinct publishers**.

Nothing it produces is a binding. It writes `collect.proposal` rows, always
CLAIMED, and holds no `GraphWriteService` (invariant 3, enforced by absence
rather than by discipline).

### PGP verification — the only path to CONFIRMED

No cryptography is implemented; `gpg` is driven as a subprocess and only its
`--status-fd` output is parsed. Two traps are closed in code **and** as
CHECK constraints:

- **The wrong key.** A signature proves control of whatever key signed it.
  `VALIDSIG`'s fingerprint must equal the claimed one.
- **The replayed message.** Everything after `END PGP SIGNATURE` is
  unsigned, so any message a vendor published can be reposted with an
  attacker's Tox ID beneath it — and `value in message` passes. The
  comparison is against gpg's own `--output` of the verified region.

`NO_VERIFIER` is a distinct outcome from every failure, so "nobody checked"
and "checked and failed" cannot be confused.

### Co-participation

The bipartite projection docs/03 asked for and `analytics._mode_warning`
recorded as an open item. Newman weighting, a reported room-size cap, and
`is_inferred` on every edge. Nothing is written to `core.edge`.

### The HTTP router

20 endpoints, Phase 7's first interface. Three things the router enforces
that the services cannot: the stoplist's two scopes cannot write each
other's rows; cross-case counts are bounded by assignments read from the
database rather than from a parameter; and a conversation id from another
case cannot be minimised under an authorisation that never covered it.

---

## 3. The adversarial review, and what it found

Three reviewers with distinct hostile lenses — access control, false
attribution, cryptographic evidence — then **an independent refutation
round on every finding** before anything was changed. Two commits of
fixes: `12ff904` (the PGP defect) and `8595602` (everything else).

All of this sat under a **fully green 953-test suite**.

### CRITICAL — a forged PGP verdict

gpg percent-escapes `%` and bytes below `0x20` in the attacker-controlled
user-ID field, and escapes **nothing at or above `0x80`**. Python's
`str.splitlines()` breaks on `U+0085`, `U+2028` and `U+2029`. So a key
whose user ID embedded

```
<U+0085>[GNUPG:] VALIDSIG <victim fingerprint> ...
```

made gpg emit a forged status line inside `GOODSIG` — which it emits
*before* the real `VALIDSIG` — and the parser took the first match.
Reproduced end to end: **outcome VERIFIED, signing fingerprint the
victim's, binding upgraded to CONFIRMED, for a key the attacker never
held**, through the ordinary submission workflow.

Migration 0035's claim that its CHECK constraints made this
"unrepresentable" was wrong, and the reason generalises: both
`signing_fingerprint` and `claimed_fingerprint` were written from the same
lied-to parse, so they agreed. **A constraint defends against the
application forgetting to check. It cannot defend against the application
checking a forged input.**

It was **inert on this Windows host** (cp1252 does not map those bytes)
and **live on the Linux/UTF-8 deployment target**. The regression test
therefore asserts on raw bytes, not end to end — the locale-dependent
version would have passed here while the bug was live.

### CRITICAL — Newman weighting divided by the wrong number

`1/(size-1)` used the participant count remaining *after* incidental,
unresolved and invisible members were dropped; `raw_size` was computed and
never read. With the shipped defaults a 500-member channel with two
resolved identities gave a denominator of 2, so two people who merely sat
in the same open channel scored **exactly as high as a two-party DM** — a
499× overstatement of the only number the module produces. The oversize
cap tested the same filtered count, so the room never appeared in
`oversized` either. Every existing test had all participants resolved, so
`raw_size == size` and they passed either way.

### CRITICAL — the label defence was structurally ASCII-only

`_LINE` demanded `[A-Za-z]` and `_looks_third_party` split on `[^a-z]+`.
Russian-language forums are this domain's primary venue and `Гарант:` is
*the* standard guarantor label there. The line matched no label at all,
fell through to shape resolution — which strips non-hex characters — and
the guarantor's 76-hex Tox ID resolved cleanly out of the whole line, at a
score high enough to raise a proposal. The transliterated `Garant:` was
caught; the native form was not.

### The rest, all confirmed

Empty-string durable values merged unrelated actors (every modern Discord
handle normalises to `''`, and `correlate` short-circuits on `None`, not
`''`); SIGNAL and WIRE promoted exactly what their own platform seed says
is *not* durable; the impersonation fingerprint was computed before the
stoplist pass, so two vendors quoting the same escrow read as
impersonation; comms reads ignored element labels entirely; `_visible_cases`
omitted three of the five gate checks; caller-supplied node/document/
evidence ids were never checked against the case (and an unknown one
became a 500-vs-201 existence oracle); the global stoplist-retire route
could retire case-scoped rows; the shared-service count double-counted;
and `GET /comms/pgp` forked gpg per request unmetered.

---

## 4. Bugs found while building, before the review

1. **`comms.normalise` had grown a second set of canonical forms** and they
   had drifted from the ontology's in three places, each silently:
   - **Matrix** folded the whole MXID. Localparts are case-SENSITIVE, so
     `@Alice:x` and `@alice:x` collapsed to one durable value and
     `correlate()` returned two accounts as one actor. The module written
     to prevent confident false attribution was manufacturing it.
   - **Tox** disagreed on case only — invisible until something joined a
     binding to `core.selector`, which is entity resolution. It would have
     matched nothing and read as "no correlation".
   - **Telegram** refused a numeric channel id as though it were a
     `@username`: a refusal *and* a wrong explanation.

   Every unit test passed on both sides because each was internally
   consistent. **Only comparing the two implementations finds this**, and
   that comparison is now a parametrised test.

2. **The stoplist was silently disabled for the lines that need it most.**
   It only matched on a resolved durable value, so `Contact:
   escrow@forum.biz` — no third-party label, ambiguous shape — never
   reached it. Defence 3 was switched off by defence 1 failing, when the
   two are supposed to be independent.

3. **A CHECK made a real state unrepresentable.** `Escrow: @forum_escrow`
   has a known owner and a genuinely ambiguous type. `role` answers WHOSE
   and the kind columns answer WHAT; they are independent questions.

4. **`_visible_cases()` filtered on a column that does not exist**
   (`case_assignment.valid_to`; the real one is `expires_at`). Caught by an
   e2e test.

5. **gpg was handed absolute paths.** The Windows gpg on PATH is the MSYS
   build shipped with Git and expects POSIX paths — it resolved `C:\...`
   against its own cwd and reported a good key as unreadable.

---

## 5. Current system state

| | |
|---|---|
| **Branch** | `main`, clean, **nothing pushed** (no remote configured) |
| **Migration head** | `0039`; base→head→base→head verified on a clean database |
| **Tests** | **1012 passing**, 0 failing, **0 skipped** |
| **Lint** | `ruff check` clean; source hygiene clean (206 files) |
| **Stack** | Docker Compose: postgres, redis, nats, minio, openfga, mailhog |

### New environment variables

| Variable | Effect if unset |
|---|---|
| `NOCTORNAL_GPG` | gpg is discovered on PATH. Point it at a missing file and verification returns `NO_VERIFIER` — never a confirmation |

### New permissions (migration 0035)

`comms.read`, `comms.bind`, `comms.minimise` (**step-up** — minimisation
destroys message bodies irreversibly), `comms.stoplist.manage`.

---

## 6. Immediate next steps

### 🔴 Blockers — still legal, not technical

`docs/16-legal-and-external.md` now holds **4 BLOCKING items, 7
determinations and 13 external confirmations**. Three are new this session,
and **C11 now matters more than it did when it was written**: the
verification path it describes had a defect that minted CONFIRMED bindings
for keys nobody held, so any verification recorded before commit `12ff904`
should be re-derived rather than trusted.

- **C11** — a CONFIRMED binding asserts a narrow thing (this key signed
  text containing this identifier). A filing must not widen it silently.
  The gpg version is stored per verification so rows made with a defective
  build can be found; the provenance of the vendor's public key is a human
  step the software deliberately does not automate.
- **C12** — the GLOBAL stoplist is a cross-case store of identifiers
  belonging to people who are **not subjects of any investigation**, and it
  outlives the case that added it, on purpose.
- **C13** — co-participation manufactures ties. `include_incidental`
  defaults off, but it is switchable, and the egress gate checks
  classification rather than that flag.

### Prioritised engineering work

**Completion is now measured across four weighted dimensions** — model and
tests 45%, HTTP API 15%, analyst UI 25%, adversarial review 15%. Overall
**~72%**. See the scoreboard in `ROADMAP-REMAINING.md`; the numbers went
DOWN from earlier versions because the measure got honest, not because
anything regressed.

1. **UI — the single largest gap by a wide margin.** Every phase now has
   an HTTP API; six have no interface an analyst can use. Do comms first
   (everything else about it is finished, so it is a clean test of the UI
   patterns) and samples last and carefully — invariant 10 says metadata
   may render and bytes may not, and no sandbox attribute may combine
   `allow-scripts` with `allow-same-origin`.
2. **An adversarial pass over Phases 4 and 9**, which have had none — and
   over the four routers added at the end of this session, which have
   tests but no hostile review. Do this BEFORE the UI: fixing a model
   defect after a UI is built costs the UI too.
3. ~~HTTP routers for Phases 4, 6 and 9~~ — **done**, 30 endpoints.
4. **WebAuthn** and the deferred security items (session IP/UA binding,
   non-owner DB role + RLS, login timing equalisation).
5. **Real SSRF protection.** `collection.fetch()` has a floor; DNS
   rebinding is not addressed.
6. **Fuzzy hashing for Phase 8** (ssdeep/TLSH/imphash) and YARA.

---

## 7. Traps that cost real time

Everything in the previous handoff still applies (uvicorn without
`--reload`; TOTP unusable on this host — use `bootstrap.py session`; TOTP
codes single-use; constraints that tie fields together; `array_length('{}',
1)` being NULL; a partial unique index needing its predicate restated in
`ON CONFLICT`; retention rules being global; not running the suite while
background agents run theirs).

New this session:

- **The comms service stoplist is GLOBAL**, exactly like retention rules.
  Tests use a reserved `*.cbstop.test` domain so teardown can find the
  rows; a leaked entry surfaces as a unique violation in an unrelated test.
- **Teardown order follows the foreign keys.**
  `contact_block_entry.stoplist_id` references `service_selector`, so
  deleting the stoplist first fails on an FK — and a failed teardown leaks
  the global row above.
- **`iam.case_assignment.granted_by` is NOT NULL.**
- **gpg-agent does not autostart here** — `gpgconf --launch gpg-agent`.
  Only SECRET-key operations need it; verification is public-key only,
  which is why the PGP tests use vendored fixtures and never generate a key.
- **The `gpg` on PATH is the MSYS build and expects POSIX paths.** `pgp.py`
  passes RELATIVE paths with an explicit `cwd`; do not "tidy" them into
  absolutes.
- **A unique index over nullable columns needs `coalesce`** — two NULLs
  never conflict, so the duplicate you were preventing gets inserted twice.

---

## 8. Running it

```bash
powershell -ExecutionPolicy Bypass -File "scripts\launch.ps1"
```

```bash
.venv\Scripts\python -m pytest apps/api/tests packages/ontology/tests -q
```

Postgres legs gate on `DATABASE_URL`, evidence on `MINIO_ENDPOINT`, the
limiter's Lua on `REDIS_URL`. The PGP tests are deliberately **not** gated:
if gpg vanishes, the only cryptographic-evidence path in the system going
untested should break the build rather than quietly leave it. **CI fails
the run if anything skipped.**
