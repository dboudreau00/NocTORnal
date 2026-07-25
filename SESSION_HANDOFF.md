# Session handoff — 2026-07-25 (Phase 7 completion)

Written so a fresh session can resume without re-deriving anything.

> **Read order:** this file → `docs/16-legal-and-external.md` (**every
> external/legal dependency, and the only file that can stop a deployment**)
> → `ROADMAP-REMAINING.md` → `CLAUDE.md` (the twelve invariants) →
> `docs/00-decisions.md` (58 numbered decisions).

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

Four commits on `main`, **807 → 953 tests**, Alembic **0034 → 0036**.

| Commit | What |
|---|---|
| `74a055d` | Contact-block parser + the normaliser divergence it exposed (0035, 0036) |
| `ea4fbfa` | PGP signature verification, delegated to gpg |
| `25cc698` | Co-participation projection + the Phase 7 HTTP router |
| `565ea7f` | Decisions 55–58, legal register C11–C13, roadmap |

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

## 3. Bugs found that were not in the brief

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

## 4. Current system state

| | |
|---|---|
| **Branch** | `main`, clean, **nothing pushed** (no remote configured) |
| **Migration head** | `0036`; round-trips against its predecessor |
| **Tests** | **953 passing**, 0 failing, 0 skipped with the stack up |
| **Lint** | `ruff check` clean; source hygiene clean (198 files) |
| **Stack** | Docker Compose: postgres, redis, nats, minio, openfga, mailhog |

### New environment variables

| Variable | Effect if unset |
|---|---|
| `NOCTORNAL_GPG` | gpg is discovered on PATH. Point it at a missing file and verification returns `NO_VERIFIER` — never a confirmation |

### New permissions (migration 0035)

`comms.read`, `comms.bind`, `comms.minimise` (**step-up** — minimisation
destroys message bodies irreversibly), `comms.stoplist.manage`.

---

## 5. Immediate next steps

### 🔴 Blockers — still legal, not technical

`docs/16-legal-and-external.md` now holds **4 BLOCKING items, 7
determinations and 13 external confirmations**. Three are new this session:

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

1. **UI.** ACH, reports, samples, ingest, comms and governance all have
   tested services and no interface. Samples last and carefully —
   invariant 10 says metadata may render and bytes may not.
2. **HTTP routers for Phases 4, 6 and 9** — retention, break-glass,
   collection and ingest still have none.
3. **An adversarial pass over Phases 4 and 9**, which have had none.
4. **WebAuthn** and the deferred security items (session IP/UA binding,
   non-owner DB role + RLS, login timing equalisation).
5. **Real SSRF protection.** `collection.fetch()` has a floor; DNS
   rebinding is not addressed.
6. **Fuzzy hashing for Phase 8** (ssdeep/TLSH/imphash) and YARA.

---

## 6. Traps that cost real time

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

## 7. Running it

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
