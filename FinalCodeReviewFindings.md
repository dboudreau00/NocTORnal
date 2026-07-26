# Final review findings — pre-POC install & usage pass

> # ✅ REMEDIATION COMPLETE — 2026-07-26
>
> **All 18 CONFIRMED code findings (CR1–CR18), the 1 PLAUSIBLE (CP1), and
> all 21 release findings (R1–R21) have been actioned.** The two REFUTED
> items (CX1, CX2) were correctly refuted and no change was made.
>
> Verified after the work: **1257 passed, 12 skipped** across both pytest
> roots, `ruff` clean, Alembic head **0052**.
>
> **A ninth adversarial pass then reviewed this remediation and found ten
> more, two of them defects in the fixes above — including a migration
> that would have recreated the very collision it was written to remove.
> See Part III. All ten are actioned.**
>
> (The header of this document says the series runs to R22; it stops at
> R21. There is no R22.)
>
> Each finding below now carries a **`✅ FIXED`** line naming what changed.
> Two needed schema changes of their own:
>
> | Migration | Closes |
> |---|---|
> | `0051_telegram_norm_arithmetic` | CR3 — re-keys stored `TELEGRAM_ID` selectors after the decode fix |
> | `0052_truncate_guards` | CR15, CR16 — the two missing `BEFORE TRUNCATE` triggers |
>
> ### Three things worth flagging beyond the individual fixes
>
> 1. **CR3 also closed determination D8.** `docs/16`'s known-unresolved
>    Telegram collision was a *consequence* of the string-strip decode, so
>    fixing the arithmetic removed it. `comms.py`'s "KNOWN UNRESOLVED
>    COLLISION" block is now an informational note, and the README says so.
>
> 2. **R13's port trim unmasked R17.** Removing OpenFGA removed the
>    `depends_on: postgres: service_healthy` that was accidentally making
>    `compose up -d` block until Postgres was ready — which `install.sh`'s
>    wait-loop had been relying on without knowing it. The explicit timeout
>    branch went in *with* that change, not after it.
>
> 3. **One new defect was introduced and caught during this pass.** The R10
>    fix added explanatory comments *inside* the `minio-init` entrypoint,
>    which is a YAML **folded** scalar — so the `#` joined onto one shell
>    line and commented out the very `mc mb … noctornal-samples` it was
>    describing. `docker compose config` caught it; reading the diff did
>    not. The comments now live outside the block, with a note saying why.
>    Recorded here because it is the ninth instance of this project's
>    recurring shape: **a defence that is written, present, and not
>    actually connected.**

---

# Part III — the ninth adversarial pass (2026-07-26, over Part I + II's own fixes)

The remediation above was itself reviewed. Ten findings, three confirmed
by execution rather than inspection. **All ten actioned; two were defects
in the fixes themselves.**

| # | Sev | Finding | Status |
|---|---|---|---|
| 1 | HIGH | `/captures/{id}/screenshot` composed the CAPTURE's labels and never checked the EXHIBIT's own; `EvidenceService.view()` has no authorisation of its own | ✅ fixed |
| 2 | HIGH | **Migration 0051 was wrong** — it re-keyed channel selectors into the USER namespace, recreating the collision CR3 removed | ✅ rewritten |
| 3 | HIGH | An attacker-appended `Authentication-Results` header WON, minting a forged "cryptographically authenticated" durable domain | ✅ fixed |
| 4 | MED-HIGH | Ordinary multi-signature mail violated `email_dkim_domain_needs_pass` → 500 with an orphaned WORM exhibit | ✅ fixed |
| 5 | MED | Cross-case evidence existence oracle on the capture path (create and read) | ✅ fixed |
| 6 | MED | CR1 clamped the release path but audited the UNCLAMPED value | ✅ fixed |
| 7 | MED-LOW | `defang()` returned a scheme-less host untouched | ✅ fixed |
| 8 | MED-LOW | With no trusted MTAs configured, the VICTIM'S OWN relay IP was proposed as durable actor infrastructure | ✅ fixed |
| 9 | LOW | CR6's fix left a comment describing behaviour it had just changed | ✅ fixed |
| 10 | LOW | Unvalidated free-form fields reached the driver as 500s | ✅ fixed |

## The two that were defects in the remediation

**#2 is the serious one, and it was mine.** Migration 0051 transformed
`norm_value` in place. But the OLD `telegram_id_norm` had *already*
stripped the `-100` prefix, so a Bot-API channel was stored as a bare
positive with no leading minus — and the rewrite, keyed on `^-`, missed it
and stamped a CHANNEL as `u:`:

| raw | old `norm_value` | in-place rewrite | correct |
|---|---|---|---|
| `-1001234567890` | `1234567890` | `u:1234567890` ✗ | `c:1234567890` |
| `-1000123456789` | `0123456789` | `u:123456789` ✗ | `c:123456789` |

A later observation of user `1234567890` would then have matched that
strong selector and auto-merged a person onto a channel — precisely the
harm CR3 exists to remove, recreated by the migration written to remove
it. It could also have aborted mid-upgrade on the unique constraint. And
the docstring's claim that it "can only reduce collisions, never create
them" was simply false.

Rewritten to re-derive from **`raw_value`**, which is not lossy, with two
pre-flights: one that refuses to run if any two rows would collapse onto
one selector (merging selectors is a case decision, not a migration's),
and one that reports how many rows may ALREADY be wrongly merged — which
recomputation cannot fix and which the migration now says out loud.

**#3 is the same shape as the Phase 7 forged-PGP verdict.** This module
gets the trust direction right for `Received` — MTAs prepend, so index 0
is the recipient's own and trust decays upward — and then read
`Authentication-Results` last-wins, which is the exact inverse. An
attacker appending their own `dkim=pass header.d=microsoft.com` had it
override the real `dkim=fail`, and `microsoft.com` came out as a
**durable** DOMAIN selector labelled "the only cryptographically
authenticated field in the mail". The `email_dkim_domain_needs_pass`
CHECK could not help: the parser made the result and the domain agree on
the forged value. *A constraint defends against the application forgetting
to check, never against it checking a forged input.*

## And one more instance of the recurring shape

Finding #1's second half: the router docstring asserted that a caller
"cannot name" an evidence id, so the attach-any-exhibit pivot "does not
exist". `CaptureIn.screenshot_evidence_id` is caller-supplied. **The
guard was documented, believed, and absent** — the tenth instance in this
project of a defence that is written and not connected.

---

# Part IV — the tenth pass (2026-07-26, independent verification of Parts I–III)

**Scope:** verify that the remediation and the ninth pass's own fixes are
*real and connected* — this project's signature failure is "a defence that
is written, present, and not connected", so a fix is not trusted here until
its code is read and, where possible, executed. Plus a fresh look at the
newest code (the deception subsystem) for anything missed.
**Method:** read the three critical ninth-pass fixes against their code;
compared migration 0051 to the runtime normaliser line by line; ran the
full suite, `ruff`, `alembic current`, and `docker compose config` on this
host; traced the DKIM/A-R selector path end to end.

## The headline: the remediation holds up

Everything I could verify, verified. This is the first pass in the project's
history whose main result is *confirmation* rather than new criticals.

| Claimed fix | Independently confirmed |
|---|---|
| **Migration 0051** (Telegram re-key) | Its `_NEW_NORM` SQL matches runtime `telegram_id_norm` **exactly** — same four branches, same `u:`/`c:`/`g:` output, both drop leading zeros. Arithmetic decode is correct for the 9-, 10- and 11-digit channel cases the old string-strip got wrong. Both pre-flights (collision-refusal, already-merged report) are sound and it is idempotent (`norm_value !~ '^[ucg]:'`). |
| **Migration 0052** (TRUNCATE guards) | Statement-level `BEFORE TRUNCATE` triggers + `REVOKE` on both `core.purge_tombstone` and `lab.sample_access`. Correct — a row-level trigger genuinely does not fire on TRUNCATE. |
| **Ninth-pass #3** (email `Authentication-Results` trust) | Only `auth_headers[0]` (the prepended, receiving-MTA header) is believed; per method, any PASS wins and carries its own domain; multi-header is flagged as a gap and stored in `auth_results_raw`. The `email_dkim_domain_needs_pass` constraint is now satisfiable by construction. |
| **Ninth-pass #8** (Received → INFRA) | `selector_candidates_for_email` refuses to propose any infrastructure when no trusted MTA is configured (all hops `boundary_is_assumed`), with an explicit "hop 0 is the victim's own relay" explanation. |
| **Ninth-pass #1** (capture screenshot auth) | Code matches the docstring guard-for-guard: create-time verification of every caller-supplied evidence id (404 on nonexistent **or** cross-case — no oracle), then on read a double gate (capture case + the exhibit's **own** labels via `authorize_object`), hostile-markup 409 *after* the auth checks, magic-byte type re-derivation, and `CSP: default-src 'none'; sandbox` + `nosniff` + CORP. |
| **Release R1–R5, R10, R13, R21** | Present in the files, not just asserted: `alembic`/`SQLAlchemy` are now `apps/api` runtime deps; `package_release.ps1` uses `git archive`; `minio-init` creates `noctornal-samples`; `install.sh` calls `create-user`; `install.ps1` uses `Invoke-Capture` (6×); compose is down to 5 services; `mailhog`→`mailpit`. |

**Numbers, by execution on this host:** `1257 passed, 12 skipped` with the
full `.env.local` loaded; `ruff` clean; Alembic head **0052**; `docker
compose config` valid, and all three `mc mb` lines survive the YAML folding
(the ninth-pass folded-scalar bug has not regressed).

## Two new findings

### TR1 — MEDIUM — DKIM→durable-DOMAIN selector is not gated on a trust anchor, while its sibling Received→INFRA path is

- **Subsystem:** deception (Phase 9) · **Files:** `deception.py:462-508`
  (`parse_eml` A-R handling), `deception.py:744-748`
  (`selector_candidates_for_email`)

The ninth pass fixed two halves of one idea and left them asymmetric.
`selector_candidates_for_email` **refuses** to mint an infrastructure (IP)
selector when no trusted MTA boundary is configured — "unconfigured means
unknown, and the honest output for unknown is nothing" (`deception.py:775`).
But three lines up, it mints a **durable** `DOMAIN` selector whenever
`dkim_result == "PASS"`, with no equivalent trust anchor, labelled to the
analyst as *"the only cryptographically authenticated field in the mail."*

The believed verdict comes from `auth_headers[0]`. That is the receiving
MTA's header **only if the receiving side authenticated inbound mail** (its
MTA prepends, so its header lands at index 0). If it did **not** — an SMB
with no inbound DKIM/DMARC checking, or a message that arrived by
`VICTIM_SUPPLIED` / `ANALYST_UPLOAD` / had its `Authentication-Results`
stripped — then the only A-R header present is the one the **attacker wrote
into their own message**, it sits at index 0, and it is believed. A crafted
`dkim=pass header.d=trusted-bank.com` then becomes a durable DOMAIN selector
wearing the "cryptographically authenticated" label — attacker-controlled
bytes presented as the one field the analyst is told to trust (docs/19 §1.2).

**Reachability / severity:** this is narrower than the pre-ninth-pass bug
(which fired even *with* a genuine header, via append-last-wins — that half
is correctly closed). It requires the capture to lack a genuine index-0
A-R header, which is realistic for BEC against SMB targets and for
victim-supplied `.eml`. It is **not** an auto-merge: `DOMAIN` is
`is_strong=False` (`definition.py:256`), so this is a *proposal* an analyst
disposes (invariant 3), not a silent graph write. The harm is a misleading
high-confidence provenance label, not node fusion — hence MEDIUM, not HIGH.
It is the same *class* the ninth pass fixed for IPs, applied inconsistently.

**Fix (mirror the Received treatment):** gate belief in an
`Authentication-Results` header — and the durable DOMAIN selector /
"authenticated" label — on a configured trusted authserv-id (a new
`NOCTORNAL_TRUSTED_AUTHSERV_ID`, sibling to `NOCTORNAL_TRUSTED_MTA_HOSTS`).
With none configured, record `dkim_result` for display but do **not** emit a
durable selector or call it authenticated — downgrade it to a claim, exactly
as the IP path already downgrades to "nothing proposed."

### TR2 — LOW — Seven DB-backed tests fail (not skip) when `DATABASE_URL` is set without `MINIO_*`

- **Files:** `apps/api/tests/test_deception_pg.py` (5 tests),
  `apps/api/tests/test_governance_http_e2e.py` (2 tests)

These tests call `EvidenceService.ingest`, which constructs
`EvidenceStorage()` and raises `EvidenceError` when `MINIO_ENDPOINT`/
`MINIO_ACCESS_KEY`/`MINIO_SECRET_KEY` are absent — but they are gated only on
`pytest.mark.skipif(not DATABASE_URL)`. So on a machine with Postgres up but
the MinIO vars not exported, they **fail rather than skip** (reproduced: 7
failed → 7 passed once `.env.local` was loaded). This refines **R7**: a
recipient who exports just `DATABASE_URL` to reach the documented
"1257 passed" sees seven hard failures and concludes the build is broken.

**Fix:** gate these on storage availability too (skip when `MINIO_ENDPOINT`
is unset), or have INSTALL.md's verify step say the DB-backed run needs the
full `.env.local` sourced, not `DATABASE_URL` alone.

## Bottom line

Ten passes in, the deception subsystem and both fix-the-fix migrations
survive independent scrutiny with their code matching their prose — the
recurring "written but not connected" defect does **not** recur in the
ninth-pass repairs. The two items above are a genuine residual (TR1, same
class as a fix already made, one-sided) and a test-hygiene gap (TR2). Neither
blocks the POC; TR1 is worth closing before the email subsystem is pointed at
real BEC. As ever, this is a code-quality assessment and says nothing about
the four BLOCKING legal items (L1–L4), which gate operation regardless.

---

**Date:** 2026-07-26
**Scope:** the Alpha release delivery — `release/` (installers, INSTALL, README,
MANUAL, CHANGELOG), `scripts/launch.ps1` / `launch.sh` / `bootstrap.py` /
`assemble_release.ps1`, `infra/docker-compose.yml`, packaging metadata, and the
four entry documents — reviewed as a *fresh recipient* would meet them.
**Out of scope:** application code quality (covered by the separate code
review). This pass asked one question: *what breaks when somebody who is not
this machine installs and uses it?*
**Method:** static read of every file above, cross-checked against the code it
invokes, plus empirical tests on this host (PowerShell 5.1 behaviour, pip
dependency closure, pytest collection). Nothing in the repository was changed
by this review. Each finding states its evidence; the one item that could not
be reproduced here is marked **inferred**.

Finding IDs are `R1`–`R22` (release review), a separate series from the
`F`-numbers in `docs/17-flagged-for-review.md`.

**Verdict in one sentence:** the product is in better shape than its delivery —
neither one-shot installer has ever survived a machine that was not already set
up, and the docs promise several things the shipped code does not do. Most
fixes are one to five lines.

---

## A. Delivery packaging — decide before anything else

### R1 — The assembled release folder is not standalone · BLOCKER (if handed over alone)

> **✅ FIXED (2026-07-26).** `scripts/package_release.ps1` replaces it — exports the whole tree via `git archive` and verifies the result. `assemble_release.ps1` now states in red that its output cannot install anything.

`scripts/assemble_release.ps1` copies **only the six files in `release/`**.
The installers then locate the application by probing for `alembic.ini` in and
beside their own directory (`release/install.ps1:41-50`,
`release/install.sh:96-105`); the final fallback is the **hardcoded** sibling
name `NocTORnal - Social Network Analysis software`. That resolves on the dev
machine and almost nowhere else. A recipient who receives the assembled folder
alone gets "the application source could not be found", and the error's first
suggestion ("put it next to the application source directory") silently fails
for any folder name other than the hardcoded one.

**Consequence:** the polished handoff artifact cannot install anything.
**Fix:** deliver the full tree with `release/` inside it (see R2); or make
`assemble_release.ps1` copy the source tree; at minimum make it print, loudly,
that the folder is docs+installers only. The locator could also scan siblings
for `alembic.ini` instead of hardcoding one name.

### R2 — Delivery must be `git archive`, never a zip of the working tree · BLOCKER (if zipped)

> **✅ FIXED (2026-07-26).** `package_release.ps1` uses `git archive`, which exports the COMMIT, so `.env.local`, `.venv`, `.git`, `screenshots/` and `shots/` cannot be included. It then asserts their absence and fails loudly if any appear.

A zip of the working directory ships:

- **`.env.local` — the real dev TOTP KEK.** Double damage: the secret leaks,
  *and* both installers see the file exists and skip secret generation
  (`install.ps1:196-198`, `install.sh:226-227`), so the recipient runs on the
  dev key and never receives an ingest pepper (the dev file holds only
  `NOCTORNAL_TOTP_KEK`).
- **`.venv`** — a copied Windows venv passes `install.ps1`'s existence check
  (`install.ps1:157`, `Test-Path` on `Scripts\python.exe`) but its
  `pyvenv.cfg` points at the dev machine's Python; pip then fails and the
  script's diagnosis ("no network access, or a corporate proxy") is wrong.
  `install.sh` handles the foreign-venv case explicitly; `install.ps1` does
  not.
- `.git` (full history), `screenshots/` and `shots/` — the latter are renders
  of real case panes; `.gitignore:22-32`'s own comment classifies them as the
  same disclosure as the case file.

**Verified clean for archiving:** `release/install.sh` is LF on disk
(`git ls-files --eol`: `i/lf w/lf`, 0 CRLFs, valid shebang), the
`.gitattributes` rules are effective, and both `.ps1` installers are pure
ASCII with no BOM.
**Fix:** produce the deliverable with `git archive` or a fresh clone. Nothing
else is safe.

---

## B. Install stoppers on a clean machine

### R3 — `alembic` is installed by nothing · BLOCKER (both platforms)

> **✅ FIXED (2026-07-26).** `alembic>=1.13` and `SQLAlchemy>=2.0` moved into `apps/api` runtime dependencies. The schema is not optional, so the thing that applies it is a dependency.

`alembic` and `SQLAlchemy` exist only in `db/requirements.txt`. They are not
dependencies of `noctornal-api` (`apps/api/pyproject.toml`) and nothing pulls
them transitively — **verified**: `pip show alembic` in the dev venv reports an
empty `Required-by:`. Both installers run only
`pip install -e packages/ontology -e apps/api` and then invoke alembic.

- **Linux:** `install.sh:287` dies with
  `.venv/bin/alembic: No such file or directory` — a raw bash error, no
  remedy, `set -e` exit.
- **Windows:** `install.ps1` hands off to `launch.ps1`, whose preflight probe
  (`launch.ps1:128`) imports `alembic` and fails **with the correct remedy
  printed** (it names `db\requirements.txt`) — recoverable, but the "one
  command" promise is broken on every fresh machine.

The dev machine never felt this because its venv predates the installers.
**Fix (pick one):** add `alembic>=1.13` to `apps/api` dependencies, or make
both installers also install `-r db/requirements.txt`.

### R4 — `install.sh` calls a bootstrap subcommand that does not exist · BLOCKER (Linux/macOS)

> **✅ FIXED (2026-07-26).** `install.sh` now prompts for email + display name and calls `create-user`. The prompt text matches what actually happens (the password is generated, not asked for), and a blank answer skips with the command to run later.

`install.sh:308` runs `bootstrap.py init`. `bootstrap.py` registers no `init`
(**verified** against `_build_parser()`, `bootstrap.py:1120-1233`; the real
command is `create-user --email … --name …`). argparse exits 2, `set -e` kills
the install at the account-creation step — even after R3 is fixed.
`INSTALL.md`'s description ("You will be asked for an email and a password")
describes an interactive wrapper that was never written; `create-user` is
flag-driven and *generates* the password.
**Fix:** call `create-user` with prompted values, or add an interactive `init`
subcommand matching the doc.

### R5 — `install.ps1` crashes with a raw RemoteException on Windows PowerShell 5.1 · HIGH

> **✅ FIXED (2026-07-26).** `Invoke-Capture` copied from `launch.ps1` into `install.ps1` and used for the Python probe, `docker info` and the pip dev-extras install.

**Empirically confirmed on this host (PS 5.1.26100):** with
`$ErrorActionPreference = 'Stop'`, redirecting a native command's stderr
(`*> $null` or `2>$null`) throws `RemoteException` the moment the command
writes to stderr. In `install.ps1` that is:

- `install.ps1:139` — `& docker info *> $null`. `docker info` writes to stderr
  exactly when the engine is down, i.e. the script crashes **in the precise
  case its friendly "start Docker Desktop" message exists for**.
- `install.ps1:103` — the Python probe `2>$null`. On a fresh Windows box the
  Microsoft Store `python` alias fires first and (**inferred** — the throw
  mechanism is proven above; the alias's use of stderr is documented but was
  not reproducible on this machine) kills the loop before `python3`/`py` are
  tried.

PS 5.1 is the default shell on Windows, and `#Requires -Version 5` blesses it.
`launch.ps1` documents this exact hazard and carries the fix
(`Invoke-Capture`, `launch.ps1:73-91`); `install.ps1` does not use it.
**Fix:** reuse the `Invoke-Capture` pattern (or relax EAP around native
calls) in `install.ps1`.

### R6 — `INSTALL.md`'s entry commands are blocked before they start · HIGH

> **✅ FIXED (2026-07-26).** `INSTALL.md`'s short version now shows `powershell -ExecutionPolicy Bypass -File …` and `chmod +x … && ./…`, with a paragraph on why neither prefix is optional.

- Windows: the doc says bare `.\install.ps1`. Default client ExecutionPolicy
  is `Restricted`, and files extracted from a downloaded zip carry
  Mark-of-the-Web — blocked either way. `QUICKSTART.md` already documents the
  working form (`powershell -ExecutionPolicy Bypass -File …`); `INSTALL.md`
  omits it.
- macOS/Linux: `./install.sh` from a zip has no execute bit. The `chmod +x`
  warning exists — but `assemble_release.ps1` prints it to the *assembler*,
  not to the recipient.

**Fix:** put both invocations, with the bypass and the chmod, in
`INSTALL.md`'s "short version".

---

## C. Usage errors in the first hour

### R7 — The documented verification step "fails" for every recipient · HIGH (credibility)

> **✅ FIXED (2026-07-26).** `INSTALL.md` states the preconditions as a table, gives the expected result WITHOUT `DATABASE_URL` (~700 skips, a correct result), corrects the figure to 1252/12, reconciles the GnuPG claim, and warns that a DB-backed run writes permanent append-only rows.

`INSTALL.md` and `CHANGELOG.md` promise **"1206 passed, 0 skipped."**
**Verified:** 1206 tests collect, but **37 files (~708 test functions — more
than half the suite) are gated on `DATABASE_URL`** being set
(`pytest.mark.skipif`, e.g. `apps/api/tests/test_cases_pg.py:13`), and no
fresh terminal has it — the installers persist only the KEK and pepper to
`.env.local`, and nothing loads even those into a new shell. Separately,
`apps/api/tests/test_pgp.py:70` hard-asserts gpg on PATH (deliberate,
fail-not-skip) while `INSTALL.md` lists GnuPG as *optional*.

A recipient who runs the verify command sees ~700 skips (or PGP failures on a
gpg-less machine), against a doc that promised zero. They will conclude the
install is broken or the numbers were inflated.

Also worth documenting: running the full suite *with* `DATABASE_URL` writes
permanent rows into the append-only tables (`audit.event`, custody) of the
recipient's fresh database — by design, but startling in a clean POC.
**Fix:** INSTALL.md must state the preconditions for the 1206/0 figure (stack
up, `DATABASE_URL` exported, gpg on PATH) and give the expected result
*without* them; reconcile the "GnuPG optional" claim.

### R8 — The Windows install never creates an account, and the doc says it does · HIGH

> **✅ FIXED (2026-07-26).** A Windows note in step 6 explains that `launch.ps1` prints the banner and then floods it off screen, with the exact `create-user` command. Works in a fresh shell now that R9 is fixed.

`INSTALL.md` step 6: "Creates your account … and prints the enrolment QR."
True only for the (currently broken, R4) Linux path. On Windows,
`launch.ps1:456-474` prints a banner telling the user to run `create-user` in
a second terminal — then starts uvicorn, whose log floods the banner off the
screen. The recipient reaches the login screen with no credentials and no
visible reason.
**Fix:** either create the account in `install.ps1` before the hand-off, or
make the doc match the banner reality.

### R9 — Every documented "second terminal" bootstrap command fails in a fresh shell — and the KEK error's advice poisons accounts · HIGH

> **✅ FIXED (2026-07-26).** `bootstrap.py` gained `_load_env_local()`, called first in `main()`; existing environment variables win. The KEK failure now detects an existing `.env.local` and says **DO NOT generate a new key**, naming the file. Both installers persist the full service config, not just the two secrets. Verified: `list-users` runs in a shell with no exports.

`bootstrap.py` requires `DATABASE_URL` and `NOCTORNAL_TOTP_KEK` from the
environment and **never reads `.env.local`** (**verified**:
`_require_database_url` / `_require_kek`, `bootstrap.py:87-117`; no env-file
loading anywhere in the script). `launch.ps1` and `open-ui.ps1` both
self-load `.env.local` — the pattern exists in-repo; `bootstrap.py` lacks it.
So `INSTALL.md`'s TOTP bypass (`session`), `QUICKSTART.md`'s
`create-user`/`demo-case`/`demo-network`, and `launch.ps1`'s own banner
command all fail in a fresh terminal.

The dangerous half: the KEK failure message (`bootstrap.py:108-116`) says
**"Generate 32 random bytes"** — with no mention that an installed system
already has *the* key in `.env.local`. A user who follows it during
`create-user` seals the new account's TOTP secret under a throwaway KEK the
API does not hold. Every subsequent login fails as `bad_totp`,
indistinguishable from a mistyped secret; `reenrol-totp` run in the same
poisoned shell repeats the damage.
**Fix:** have `bootstrap.py` load `.env.local` (mirroring `open-ui.ps1`), and
change the KEK error to say "copy the value from `.env.local`" when that file
exists.

### R10 — The first real sample upload hits a bucket nothing creates · HIGH

> **✅ FIXED (2026-07-26).** `mc mb --ignore-existing local/noctornal-samples` added to `minio-init`, deliberately WITHOUT `--with-lock` (docs/11's rejection path must be able to destroy sample bytes). Bucket confirmed created.

The samples store defaults to bucket `noctornal-samples`
(`apps/api/src/noctornal_api/samples.py:429`). **Verified:** compose's
`minio-init` creates only `noctornal-evidence` and `noctornal-raw`
(`infra/docker-compose.yml:67-75`); `make_bucket` exists only in
`rawstore.py`; and `seed_lab_demo.py:125-140` deliberately uses a null store
("writes nowhere") — which is why the dev machine, whose Lab pane is seeded,
has never exercised this path. A recipient who declares the documented dev L1
policy vars and uploads a sample gets an uncurated storage error
(NoSuchBucket) where every other refusal in the system is explained.
**Fix:** one line in `minio-init`:
`mc mb --ignore-existing local/noctornal-samples` (decide deliberately
whether it carries `--with-lock`; evidence does, raw deliberately does not).

### R11 — Email capture does not work out of the box · MEDIUM

> **✅ FIXED (2026-07-26).** Both installers write `SMTP_HOST=localhost`, `SMTP_PORT=1025` and `SMTP_ALLOW_PLAINTEXT=1` into `.env.local`, so the advertised Mailpit demo works.

`SMTP_HOST` unset → `TransportError("SMTP_HOST is not set")`
(`transports.py:212-214`); even pointed at Mailpit, the default `SMTP_PORT`
is **587** (`transports.py:215`), not Mailpit's 1025, and plaintext requires
`SMTP_ALLOW_PLAINTEXT=1`. Neither installer nor launcher sets any of the
three, yet `launch.ps1` advertises "Mailpit (captured e-mail)" and
`INSTALL.md` lists Mailpit among the containers Docker is needed for. The
in-app Inbox works regardless; the e-mail demo silently doesn't.
**Fix:** either export the three dev values in the launchers, or document
them where Mailpit is advertised.

### R12 — Demo-path refusals worth pre-empting · LOW

> **✅ FIXED (2026-07-26).** Documented rather than changed — both are refusals behaving as designed. Recorded in `release/MANUAL.md`'s refusals table and in the README's TOTP note.

Both are documented refusals behaving as designed; both will still stall a
demo that has not prepared for them:

- **Break-glass** refuses outright on a default single-account install —
  nobody holds `SECURITY_OFFICER` (`MANUAL.md` refusals table). Seed a second
  user with that role if break-glass will be shown.
- A login via the `session` bypass (the doc's own recommendation on
  clock-broken hosts) leaves **step-up-gated actions** (merge, export, purge,
  sample download) refusing until a real TOTP login exists.

---

## D. Environment and platform risks

### R13 — Ten published host ports; two dead containers own four of them · MEDIUM-HIGH

> **✅ FIXED (2026-07-26).** OpenFGA and NATS removed from the compose file with the reasoning inline, including a note for whoever re-adds OpenFGA about the `service_healthy` side effect. Ten published ports became six. `docker compose config` validates.

The compose publishes 5432, 6379, 9000, 9001, 1025, 8025, 8080, 3001, 4222,
8222 (+ API 8000). One collision fails the entire `docker compose up`. The
likely offenders on a real workstation are **5432** (any local Postgres) and
**8080**. **Verified:** `OPENFGA` and `NATS` are referenced *nowhere* in
`apps/api` — the containers are dead weight for the POC, yet own
8080/3001/4222/8222 and can sink the install by themselves. (`install.sh`
also exits on compose failure with no remedy text; `launch.ps1:222-228` has
one, and its port list omits 1025/3001/8222.)
**Fix:** for the POC compose, drop OpenFGA and NATS (or at least stop
publishing their ports); Mailpit can stay if R11 is wired.

### R14 — `QUICKSTART.md` suggests `-Port 8080` as the alternate API port · LOW

> **✅ FIXED (2026-07-26).** `QUICKSTART.md` now suggests `-Port 8010` and says why not 8080.

That is OpenFGA's published port; with the stack up the suggestion collides
by construction. `launch.ps1`'s port pre-check catches it, but the example
should be a free port.

### R15 — Python 3.12 is accepted but has never run this code here · LOW

> **✅ FIXED (2026-07-26).** Documented in the README prerequisites table: 3.12 is the minimum, 3.13 is what it is developed and tested on daily. A clean 3.12 run is still the honest way to settle it.

Installers and `pyproject` accept `>=3.12`; the product has only ever run on
3.13 on this machine. All dependencies publish 3.12 wheels, so this is
probably fine — but "probably" is untested. One clean 3.12 run settles it.

### R16 — `install.ps1` never verifies Compose v2 · LOW

> **✅ FIXED (2026-07-26).** `install.ps1` checks `docker compose version` with remedy text, matching `install.sh`.

`install.sh` checks `docker compose version`; `install.ps1` checks only
`docker` and `docker info`. A podman-aliased or CLI-only Docker on Windows
passes the checks and fails later at `compose up`. Docker Desktop bundles
Compose, so the population hitting this is small.

### R17 — `install.sh`'s Postgres wait-loop has no failure branch · LOW

> **✅ FIXED (2026-07-26).** `PG_READY` flag plus an explicit `stop_with` branch naming both usual causes (half-initialised volume, port 5432 taken) and the `down -v` recovery. Went in with R13, which unmasked it.

`install.sh:270-277`: if 60 probes exhaust, the loop simply ends and the
script proceeds to migrations, which fail with a raw psycopg traceback. In
practice `docker compose up -d` already blocks on the postgres healthcheck
(via `openfga-migrate`'s `service_healthy` condition), which masks this —
and removing OpenFGA per R13 would unmask it. Add an explicit timeout branch.

---

## E. Documentation drift the recipient will notice

### R18 — Root README sends readers to a document that says the schema has never run · MEDIUM

> **✅ FIXED (2026-07-26).** `GETTING-STARTED.md` moved to `docs/ARCHIVE-2026-07-24-getting-started.md` with an ARCHIVED banner quoting its own false claim and pointing at `release/INSTALL.md`. The rewritten root README leads with the installers.

`README.md`'s table marks `GETTING-STARTED.md` "**Read first**" — and that
file still says *"Nothing has been executed. The schema has never touched a
real Postgres"* (true on 2026-07-24, wildly false at Alembic 0045 / 1206
tests). An evaluator obeying the README meets a project that appears not to
know its own state within five minutes.
**Fix:** retire or clearly date-stamp `GETTING-STARTED.md`; make the root
README lead with `release/INSTALL.md`.

### R19 — `QUICKSTART.md` contradicts shipped features · LOW-MEDIUM

> **✅ FIXED (2026-07-26).** `QUICKSTART.md` corrected: recovery codes exist (`bootstrap.py recovery-codes`), rate limiting and the destination-aware egress gate both shipped. The 'still missing' list now matches `docs/17`.

"Recovery codes … are **not built yet**" — `bootstrap.py recovery-codes`
exists. "Still missing: rate limiting" — the Redis GCRA limiter shipped
(`pyproject`, `INSTALL.md`). Stale claims in the doc most likely to be read
second.

### R20 — `INSTALL.md` gives Unix-only paths for commands Windows recipients must run · LOW

> **✅ FIXED (2026-07-26).** Windows paths added beside the Unix ones throughout `INSTALL.md`; the Docker row now says four containers and ~3 GB RAM.

Every bootstrap example is `.venv/bin/python …`; on Windows it is
`.venv\Scripts\python`. The doc also says Docker runs "Postgres, Redis,
MinIO, Mailpit" — the stack starts six services, and the RAM estimate should
reflect that (or R13 should shrink the stack to match the doc).

### R21 — Cosmetics · LOW

> **✅ FIXED (2026-07-26).** Compose service renamed `mailhog` → `mailpit`; `ARCHITECTURE.md` updated. The `httpx2` deprecation warning is upstream and left alone.

The Mailpit service is named `mailhog` in the compose file; the verify run
prints a `StarletteDeprecationWarning` ("install `httpx2`") above its result;
`install.sh --help` works but prints the header comment including its own
usage twice-removed. None blocks anything; all are visible to the recipient.

---

## F. What held up under review

Recorded so the next pass does not re-audit it:

- **`launch.ps1` is careful and honest** — `Invoke-Capture` for the PS 5.1
  hazard, health-wait with correct recovery advice (including the
  half-initialised-volume case), port pre-check, remedy text that names real
  files.
- **Secrets handling is right** in both installers: no defaults anywhere,
  fresh 32-byte values, `chmod 600` on Unix, existing files never overwritten,
  and the loss consequence stated at generation time.
- **The compose file's reasoning is sound** — pgvector image, TCP-forced
  healthcheck (with the unix-socket false-healthy trap documented), object
  lock on evidence created correctly-or-visibly-failed, raw bucket
  deliberately lock-free with the reason in a comment.
- **`release/MANUAL.md` matches the code** everywhere spot-checked: the 451
  policy gate, the sample-origin refusal, the notify-domain refusal, the live
  dot (`NOCTORNAL_LIVE` defaults on), the step-up list.
- **The test-count claim is real** (1206 collected) and the suite's core is
  deliberately DB-free (`conftest.py` defaults only a deterministic test
  KEK), so a no-env run is meaningful — it just isn't the promised number
  (R7).
- **Line-ending hygiene is done**: `.gitattributes` verified effective,
  `install.sh` LF on disk, installers pure ASCII/no-BOM against the PS 5.1
  code-page trap.

---

## G. Recommended order of work

The pattern across R3/R4/R9/R10 is one pattern: **the installers and the
sample-storage path have never run end-to-end on a machine that was not
already set up** — 1206 green tests, none of which runs the installer.

1. **Clean-machine dry run** (VM, or deleted `.venv` + throwaway data dirs):
   both installers, end to end, then create an account, log in with a real
   phone, upload one real sample. This single exercise witnesses R3–R10.
2. Fix the blockers: R3 (alembic dependency), R4 (`init` → `create-user`),
   R5 (`Invoke-Capture` in install.ps1), R2/R1 (delivery = `git archive`,
   assembler honesty).
3. Fix the first-hour traps: R9 (bootstrap loads `.env.local`; KEK message),
   R10 (samples bucket), R7/R8 (INSTALL.md truthfulness), R6 (entry
   commands).
4. Trim the stack and the docs: R13, R11, R18–R20.
5. Re-run step 1 from the actual deliverable artifact.

---
---

# Part II — Application code review (multi-agent, 2026-07-26)

This is the "separate code review" Part I defers to (Part I covers delivery /
install / docs; this part covers application code quality). Appended so both
live in one findings record.

- **Baseline reviewed:** commit `d429ed9` (Alembic 0044). The tree advanced to
  `d4595ff` during the review via a concurrent session, so a few line numbers
  may have shifted and a small number of findings may already be addressed —
  re-verify against current HEAD before applying.
- **Method:** 12 read-only reviewers, one per subsystem, dependency-ordered
  Phase 0 -> UI; every finding then adjudicated by an independent adversarial
  verifier that had to construct a concrete failure to CONFIRM it, or cite the
  guard that already handles it to REFUTE it.
- **Totals:** 21 raised — **18 confirmed, 1 plausible, 2 refuted.** 1 critical,
  5 high, 6 medium, 6 low.
- **Clean subsystems (no findings):** auth & crypto (Phase 0), evidence & WORM (Phase 1).
- **ID series:** `CR1`–`CR18` (code review) — distinct from Part I's `R`-series
  and from the `F`-numbers in `docs/17`.

| ID | Sev | Verdict | Finding | File:line |
|---|---|---|---|---|
| CR1 | CRITICAL | CONFIRMED | Report builder discloses material above the caller's TLP clearance (`target_tlp` unclamped) | `http/routers/reports.py:79,146` |
| CR2 | high | CONFIRMED | Case-scoped access gate never checks `is_active`; a deactivated user keeps full read/write | `stores.py:217` |
| CR3 | high | CONFIRMED | `telegram_id_norm` mis-decodes non-10-digit channel IDs -> selector miss + channel/user false-merge | `packages/ontology/.../normalisers.py:190` |
| CR4 | high | CONFIRMED | Zero-width/format char in an escrow label defeats the third-party defence | `contact_blocks.py:231` |
| CR5 | high | CONFIRMED | `impersonation_candidates()` returns classified metadata with no clearance filter | `contact_blocks.py:1159` |
| CR6 | high | CONFIRMED | Ingest-key IP allowlist is silently unenforced (fail-closed guard is dead code) | `ingest.py:663` |
| CR7 | medium | CONFIRMED | `retract_assertion` / add-assertion authorize only at case level | `http/routers/graph.py:195` |
| CR8 | medium | CONFIRMED | Single-node projection crashes the SNA suite (NaN density -> invalid jsonb) | `analytics.py:925` |
| CR9 | medium | CONFIRMED | Persistence failure leaves `metric_run` stuck at RUNNING (FAILED contract unmet) | `analytics_runs.py:222` |
| CR10 | medium | CONFIRMED | `ProposalReview.accept` can double-apply under concurrency | `proposals.py:204` |
| CR11 | medium | CONFIRMED | `reject()` destroys sample bytes with no classification/compartment gate | `samples.py:682` |
| CR12 | medium | CONFIRMED | Victim-credential value sent as GET query param -> plaintext PII in access logs | `http/routers/ingest.py:866` |
| CR13 | medium | CONFIRMED | Inspector selector values / comms identifiers rendered without bidi substitution | `http/static/app.js:3017` |
| CR14 | medium | CONFIRMED | Search hit labels (and singly-fetched nodes) bypass the `withSafeLabel` bidi defence | `http/static/app.js:2617` |
| CR15 | low | CONFIRMED | `purge_tombstone` append-only trigger omits the TRUNCATE guard | `db/migrations/versions/0032_*.py:150` |
| CR16 | low | CONFIRMED | `lab.sample_access` append-only trigger omits the TRUNCATE guard | `db/migrations/versions/0031_*.py:242` |
| CR17 | low | CONFIRMED | Unhandled/500 responses bypass the security-header middleware | `http/errors.py:148` |
| CR18 | low | CONFIRMED | Search pane `Promise.all` blanks the whole pane on one sub-request failure | `http/static/app.js:2599` |
| CP1 | low | PLAUSIBLE | Billion-laughs DTD bypasses `parse_rss` by padding the DOCTYPE past the 8192-byte window | `collection.py:603` |
| CX1 | — | REFUTED | Element-level 403-vs-404 existence oracle | `http/deps.py` |
| CX2 | — | REFUTED | SAME_AS edge permits IDENTITY/PERSON crossing | `db/migrations/versions/0017_seed_ontology.py` |

*(`>=`/`<=` denote TLP lattice dominance; `->` denotes "leads to". Paths under `apps/api/src/noctornal_api/` unless noted.)*

## CR1 — CRITICAL — Report builder discloses material above the caller's TLP clearance

> **✅ FIXED (2026-07-26).** `_target_within_ceiling()` clamps the requested `target_tlp` to `min(requested, user_ceiling()[0])` at BOTH the build and release call sites, before `ReportBuilder` sees it. Clamped rather than rejected, so an under-cleared caller is not told the higher tier exists. The audit event records requested and effective separately.

- **Subsystem:** curation / reports (Phase 6) · **Invariant:** 8 (TLP gates egress) · **File:** `http/routers/reports.py:79` (and `:146`)

`reports.py:79`/`:146` call `user_ceiling(conn, user.user_id)` but subscript `[1]`, discarding index `[0]` — the caller's own clearance. The client `target_tlp` is validated only against the TLP name set (`:69-71`) then used verbatim: `:254` builds `GraphService(clearance=target.name)` and `:271` binds evidence `WHERE classification <= target.name`. `projections.py:185` filters nodes on `classification <= %s::core.tlp`, so a higher target strictly widens results — no clamp anywhere. Every other graph consumer uses the caller's own clearance. `require('report.generate')` checks the caller against the CASE's label (AMBER), never `target_tlp`. RED elements can legitimately live in an AMBER case; the build endpoint returns `report.as_dict()` directly with no egress gate (egress runs only on `/release`).

**Failure:** Case C is AMBER, contains a RED node. Mallory (AMBER clearance, assigned, holds `report.generate`) calls `POST /cases/C/report?target_tlp=RED`. The gate passes on the case's AMBER label; `GraphService(clearance='RED')` returns the RED node's label/type/attrs and RED exhibit titles/SHA-256/BLAKE3/acquisition_method — handed to an AMBER analyst, marked `X-TLP: RED`.

**Fix:** At build (`73-79`) and release (`144-146`), clamp the effective target to `min(target_tlp, user_ceiling(...)[0])` (or 400 if it exceeds), and pass the caller's compartments.

## CR2 — HIGH — Case-scoped access gate never checks `is_active`

> **✅ FIXED (2026-07-26).** `PgAccessResolver.resolve` now selects `WHERE id = %s AND is_active`, so an inactive account resolves to "unknown or inactive user" and the case-scoped path denies. Matches `require_global`, which already checked it.

- **Subsystem:** access gate (Phase 0) · **Invariant:** docs/05 five-part gate · **File:** `stores.py:217`

The case-scoped path never consults `is_active`. `SessionService.validate` resolves the token against `iam.session` only (no join to `app_user`); `PgAccessResolver.resolve` (`stores.py:217-218`) selects `tlp_clearance, compartments` with no `is_active` predicate; `evaluate()` has none. The asymmetry is deliberate elsewhere: login rejects inactive users (`auth.py:112`) and `require_global` adds `AND u.is_active` (`deps.py:201`). And `revoke_all_for_user` has **zero production callers**.

**Failure:** Analyst A is deactivated (`UPDATE iam.app_user SET is_active=false`) while holding a live `__Host-session`. `POST /cases/{C}/nodes` still succeeds — the cookie is accepted, `validate` passes, `resolve` reads only clearance/compartments, the assignment resolves, all five checks pass. Full read/write survives for up to the 12h absolute lifetime; deactivation never severs the session.

**Fix:** Add the `is_active` predicate to the case path (mirror `require_global`) and/or wire deactivation to `revoke_all_for_user`; ideally both.

## CR3 — HIGH — `telegram_id_norm` mis-decodes non-10-digit Bot-API channel IDs

> **✅ FIXED (2026-07-26).** `telegram_id_norm` decodes arithmetically (`-(10**12 + id)`) and namespaces by id space (`u:`/`c:`/`g:`), with an explicit prefix accepted from a caller that knows the type. Migration **0051** re-keys stored selectors and states plainly that it cannot undo a merge already made. Eight new tests cover the 9-, 10- and 11-digit cases and the collision. **This also closed determination D8.**

- **Subsystem:** ontology/selectors (Phase 1) · **Invariant:** 9 (durable ids); via strong-selector auto-merge, 3 · **File:** `packages/ontology/src/noctornal_ontology/normalisers.py:190`

Lines 190-191 reverse the Bot-API channel encoding by string-dropping a leading `100`, but the encoding is arithmetic — `chat_id = -(10^12 + channel_id)` — so the shortcut is correct only for exactly-10-digit ids. 9-digit -> spurious leading zero (miss); 11-digit (common post 64-bit migration) -> `100` strip never fires (miss); 10-digit channel id collides with a same-numbered user id. `TELEGRAM_ID is_strong=True`, so misses/collisions hit the strong-selector auto-merge path. The one test covers only the 10-digit case.

**Failure:** An 11-digit channel `12345678901`: MTProto scraper records `12345678901`; a bot export records `-1012345678901`; the two observations of one channel become two strong selectors that never merge. Separately a 10-digit channel id normalises to bare digits equal to a user id, upserting a channel and a person onto one strong-selector row (auto-merge).

**Fix:** Decode arithmetically and namespace-prefix the norm_value per Telegram type (`u:`/`g:`/`c:`); add 9-/11-digit and collision tests.

## CR4 — HIGH — Zero-width char in an escrow label defeats the third-party defence

> **✅ FIXED (2026-07-26).** `_strip_invisible()` removes Unicode categories Cf and Cc from every line before `_LINE` sees it. Category-based rather than an enumerated list. Verified: Cyrillic + ZWSP, Latin + BOM and `escrow` + LRM all now resolve THIRD_PARTY where all three previously resolved ROLE_SELF.

- **Subsystem:** comms / contact-block parser (Phase 7) · **Invariant:** 1 · **File:** `contact_blocks.py:231`

A line `Garant: <76-hex Tox ID>` where the Cyrillic guarantor label embeds a U+200B (category Cf) makes `_LINE` fail (Cf matches neither `\w` nor `\s`), so `label=None`; `_resolve_by_shape` strips all non-hex (Cyrillic + ZWSP vanish) -> 76-hex -> TOX_PK as ROLE_SELF; `_looks_third_party(None, ...)` skips its label word-set branch (gated on `if label:`) and bare "garant" lives in `_THIRD_PARTY_LABEL_WORDS`, not `_THIRD_PARTY_MARKERS`. The guarantor's key is attributed to the vendor. No Cf-stripping guard exists; the authors closed the ASCII/Cyrillic fall-through but the invisible-char variant reopens it.

**Fix:** Strip/reject Cc/Cf chars per line before parsing, and treat a folded third-party label as THIRD_PARTY even when `_LINE` didn't cleanly parse.

## CR5 — HIGH — `impersonation_candidates()` returns classified metadata with no clearance filter

> **✅ FIXED (2026-07-26).** `impersonation_candidates()` takes a REQUIRED `clearance` and composes the block's labels with its case's in SQL, exactly as the sibling `get()` does. The router threads `user_ceiling`. A default was deliberately not provided — that is the shape that caused this.

- **Subsystem:** comms (Phase 7) · **Invariant:** 8 · **File:** `contact_blocks.py:1159`

`impersonation_candidates` filters solely on `case_id = ANY(%s)` (`1159`), no classification/compartments predicate, and aggregates `publisher_handle`/`publisher_identity_node_id`/`source_ref`. The router passes no clearance. The sibling `get()` computes `user_ceiling` and gates on `classification <= %s::core.tlp AND compartments <@ %s`; its docstring says a block can be classified above its case.

**Failure:** A RED block sharing a fingerprint inside an AMBER case leaks its `publisher_handle` and `source_ref` to an AMBER analyst with `comms.read`.

**Fix:** Thread `clearance`/`compartments` from the router (`user_ceiling`) into the query.

## CR6 — HIGH — Ingest-key IP allowlist is silently unenforced (dead-code guard)

> **✅ FIXED (2026-07-26).** `authenticate()` fails closed when an allowlist is set and `peer_ip` is absent or unparseable, and the returned dict now carries `ip_allowlist`, which makes the router's second guard reachable for the first time.

- **Subsystem:** ingest (Phase 9) · **Invariant:** 11 · **File:** `ingest.py:663`

`authenticate()` enforces the allowlist only at `if allowlist and peer_ip:` (`654`) — skipped when `peer_ip` is None. The returned dict (`663-669`) OMITS `row[9]` (`ip_allowlist`), so the router guard `key.get("ip_allowlist")` (`http/routers/ingest.py:255`) is always None — dead code whose own comment describes the case it misses.

**Failure:** uvicorn behind a unix-socket proxy (`request.client is None`). A leaked key restricted to a partner CIDR is presented from any host: the CIDR check is skipped, the guard can't fire. Bounded by invariant 11 (write-only keys) — payoff is junk into quarantine, not case access — but the control is fully defeated.

**Fix:** Add `ip_allowlist: row[9]` to the returned dict, and/or fail closed in `authenticate()` when an allowlist is set but `peer_ip` is None.

## CR7 — MEDIUM — `retract_assertion` / add-assertion gate only at case level

> **✅ FIXED (2026-07-26).** `_element_labels()` resolves the element's own classification and compartments, and both `_add_assertion` and `retract_assertion` call `authorize_object` with them. Retraction matters most: it can dissolve an element from every analyst's projection.

- **Subsystem:** assertion layer (Phase 1) · **Invariant:** deps.py rule 1 (element protected by BOTH its own labels and its case's) · **File:** `http/routers/graph.py:195`

`retract_assertion` is gated only by `require('assertion.retract')` (case-level, `classification=None`) and checks `case_id`; `GraphWriteService.retract_assertion` just UPDATEs `retracted_at`, no classification check. No element label is consulted — unlike `create_node`/`create_edge` (`check_writable_labels`) and evidence (`authorize_object` with the row's labels). `_add_assertion` has the same gap. Since a RED element can live in an AMBER case and the projection requires a non-retracted assertion, retracting the last live assertion of a RED node dissolves it from every analyst's graph.

**Failure:** AMBER analyst A (holds `assertion.retract`, previously RED-cleared, recorded a RED node's last-assertion UUID) POSTs `/cases/C/assertions/{uuid}/retract`; the case-level gate passes, retract commits, the RED node disappears for everyone — destroyed by a user not cleared to see it. Medium (needs the UUID).

**Fix:** Resolve the element and `authorize_object(..., classification=elem_cls, compartments=elem_comp)` in both `retract_assertion` and `_add_assertion` (the `evidence.py:58-59` pattern).

## CR8 — MEDIUM — Single-node projection crashes the SNA suite (NaN density -> invalid jsonb)

> **✅ FIXED (2026-07-26).** `density` routed through `_clean()`, which returns `None` for NaN/inf. It was the only float in the payload not already going through it.

- **Subsystem:** analytics (Phase 3) · **File:** `analytics.py:925`

`run_suite` guards `n==0` but not `n==1`. `g.density()` on one vertex returns NaN; `round(NaN,6)` stays NaN, and density is the ONLY float not routed through `_clean()`. `psycopg` serializes literal `NaN`, which Postgres jsonb rejects -> 500. Reachable by any single-node projection (single-entity case, or TLP filtering leaving one visible node).

**Fix:** Route density through `_clean()` (or guard `n<2 -> None`).

## CR9 — MEDIUM — Persistence failure leaves `metric_run` stuck at RUNNING

> **✅ FIXED (2026-07-26).** The COMPLETE write and `_persist_node_metrics` are inside their own try/except that marks the run FAILED and audits `ANALYTICS_RUN_FAILED` with `stage: persist`. The docstring's claim that "every exception marks the run FAILED" is now true.

- **Subsystem:** analytics (Phase 3) · **File:** `analytics_runs.py:222`

The try/except (`200-218`) wraps only `compute(sub)`, though its comment claims "every exception marks the run FAILED." The COMPLETE `UPDATE ... Json(payload)` + `_persist_node_metrics` (`222-234`) is outside it. The RUNNING row was inserted autocommit. When CR8's `Json(NaN)` raises, the row is stranded at RUNNING with no FAILED status and no `ANALYTICS_RUN_FAILED` audit; each retry inserts another.

**Fix:** Extend the failure handler to cover the COMPLETE write + node-metric persistence.

## CR10 — MEDIUM — `ProposalReview.accept` can double-apply under concurrency

> **✅ FIXED (2026-07-26).** A real `SELECT … FOR UPDATE` inside the writing transaction, with the state re-checked under the lock, plus a rowcount assertion on the guarded UPDATE that rolls back rather than committing an orphan.

- **Subsystem:** curation (Phase 3) · **Invariant:** 3 · **File:** `proposals.py:204`

`get_for_update` (`317-322`) is a plain `SELECT ... WHERE id=%s` with NO `FOR UPDATE` on an autocommit connection. The graph write runs inside a transaction BEFORE the state-guarded `UPDATE ... WHERE state='PROPOSED'`, whose rowcount is never checked. Under READ COMMITTED, a second concurrent accept re-evaluates its WHERE after the first commits, matches 0 rows, raises nothing, and commits its already-created duplicate element plus a second audit event.

**Failure:** Two simultaneous accepts of proposal P each create a node (N1, N2); N2 is orphaned (not referenced by `applied_node_id`) and inflates the actor count. Medium — duplicate needing cleanup, not data loss.

**Fix:** `SELECT ... FOR UPDATE` inside the transaction before the write, and/or check the guarded UPDATE's rowcount and raise on 0.

## CR11 — MEDIUM — `reject()` destroys sample bytes with no classification/compartment gate

> **✅ FIXED (2026-07-26).** `reject()`'s route resolves the sample through `visible()` — the same label-composed predicate `download()` uses — BEFORE anything is destroyed, and returns the same 404 a nonexistent id gives.

- **Subsystem:** samples (Phase 8) · **Invariant:** 10 · **File:** `samples.py:682`

`reject()` (irreversible: deletes the object, zeroes the data key) resolves the sample via `get()` — `WHERE id = %s`, no clearance/compartment/case predicate — and the router gates only on the global `sample.analyse`, never `user_ceiling()`, unlike `download()`. A caller with the global role but no access to a RED/compartmented case can destroy a sample knowing only its UUID.

**Fix:** Resolve through the same label-composed predicate `download()` uses; return "no such sample" when the caller couldn't have seen it, before any delete.

## CR12 — MEDIUM — Victim-credential value sent as GET query param -> plaintext PII in logs

> **✅ FIXED (2026-07-26).** `GET /search?value=…` became `POST /search` with a `FingerprintSearchBody`, so the victim credential never enters a request line or an access log. Matches the sibling reveal endpoint. No HTTP callers existed.

- **Subsystem:** ingest (Phase 9) · **File:** `http/routers/ingest.py:866`

`search_by_fingerprint` takes `value: str = Query(...)`, so the raw victim credential lands in the GET request line -> uvicorn/nginx access logs, outside the compartment and PII-authorisation gate, with independent retention. The sibling reveal endpoint uses a POST body. Values are ciphertext in the DB precisely so plaintext isn't loggable; this defeats that.

**Fix:** Accept the value in a POST body (mirror the reveal endpoint).

## CR13 — MEDIUM — Inspector selector values / comms identifiers rendered without bidi substitution

> **✅ FIXED (2026-07-26).** `visibleText()` applied to `raw_value`, `norm_value`, `observed_value` and `durable_value` at all four sites.

- **Subsystem:** UI · **Invariant:** 9 · **File:** `http/static/app.js:3017` (also `3019`, `3872`, `3880`)

`renderSelectors` writes `s.raw_value`/`s.norm_value` and `renderContactBlock` writes `e.observed_value`/`e.durable_value` via `el()` (`textContent`), which stops execution but not bidi/zero-width reorder. None wrap in `visibleText()`, though the dead-letter (`5056`) and Lab filename (`6311`) sites do. Server side, `raw_value` is stored verbatim. These are attacker-chosen forum identifiers.

**Failure:** A Jabber address whose bytes embed U+202E (RLO) renders reordered in the inspector/contact-block output; the analyst reads/compares an identifier whose on-screen form differs from the correlated bytes, and two distinct selectors can render identically.

**Fix:** Wrap the four values in `visibleText()` at each site, or substitute deceptive characters at the API-landing choke point.

## CR14 — MEDIUM — Search hits / singly-fetched nodes bypass the `withSafeLabel` bidi defence

> **✅ FIXED (2026-07-26).** `renderHits` wraps `hit.label` in `visibleText()`; `loadMissingNode` pushes `withSafeLabel(n)`. A new UI-invariant test additionally constrains every `.src =` assignment to an `/api/v1/` path, closing a gap the suite had (`_INNER_HTML_WRITE` never matched `.src`).

- **Subsystem:** UI · **Invariant:** 2/9 · **File:** `http/static/app.js:2617` (also `loadMissingNode` at `2852`)

`renderHits` appends `hit.label` via `el('span', null, hit.label)` (`2617`) with no `withSafeLabel`; `loadMissingNode` does `state.nodes.push(n)` (`2852`) on the raw `/nodes/:id` record, which then feeds the inspector (`2690`). The bulk paths sanitise at landing (`nodes.map(withSafeLabel)` at `767`, `842`), with a comment warning the defence must hold at every site. Search is the primary find-by-name tool.

**Failure:** A node's IDENTITY label with U+202E renders de-fanged in graph/table/palette but raw/reordered in Search — the entity clicked reads as a different/trusted identity; `loadMissingNode` shows the raw label in the inspector.

**Fix:** Map search hits through `withSafeLabel` before `renderHits`, and apply it in `loadMissingNode` before pushing into `state.nodes`.

## CR15 — LOW — `purge_tombstone` append-only trigger omits the TRUNCATE guard

> **✅ FIXED (2026-07-26).** Migration **0052** adds `purge_tombstone_no_truncate` (`BEFORE TRUNCATE … FOR EACH STATEMENT`) plus the REVOKE. Proven: `TRUNCATE core.purge_tombstone` is refused.

- **Subsystem:** migrations (Phase 0) · **Invariant:** append-only (docs/08) · **File:** `db/migrations/versions/0032_retention_and_break_glass.py:150`

`0032:150-152` installs only a `BEFORE UPDATE OR DELETE ... FOR EACH ROW` trigger — no `BEFORE TRUNCATE`. Siblings `audit.event` (`0013:56-59`) and `evidence_custody` (`0023:32-37`) pair both; a row trigger does not fire on TRUNCATE, and `0032` has no REVOKE.

**Failure:** A TRUNCATE-privileged role (owner/app role, or superuser) runs `TRUNCATE core.purge_tombstone;` — empties the record-of-destruction ledger with no trigger dropped, while `TRUNCATE audit.event`/`evidence_custody` are rejected. Low (privilege-bounded).

**Fix:** Add `CREATE TRIGGER purge_tombstone_no_truncate BEFORE TRUNCATE ... FOR EACH STATEMENT EXECUTE FUNCTION core.block_tombstone_mutation();` (drop in downgrade).

## CR16 — LOW — `lab.sample_access` append-only trigger omits the TRUNCATE guard

> **✅ FIXED (2026-07-26).** Migration **0052** adds `sample_access_no_truncate` plus the REVOKE. Proven: `TRUNCATE lab.sample_access` is refused.

- **Subsystem:** migrations (Phase 0) · **Invariant:** sample custody append-only (docs/11) · **File:** `db/migrations/versions/0031_lab_samples.py:242`

Same as CR15: `0031:242-244` installs only the row trigger despite a docstring claiming equivalence to `audit.event`; no `BEFORE TRUNCATE`, no REVOKE.

**Failure:** `TRUNCATE lab.sample_access;` erases the entire custody record of who downloaded/shared/detonated a live hostile binary and when, no trigger dropped. Low (privilege-bounded).

**Fix:** Add `CREATE TRIGGER sample_access_no_truncate BEFORE TRUNCATE ... FOR EACH STATEMENT EXECUTE FUNCTION lab.block_access_mutation();` (drop in downgrade).

## CR17 — LOW — Unhandled/500 responses bypass the security-header middleware

> **✅ FIXED (2026-07-26).** `_unhandled` stamps `_SECURITY_HEADERS` onto the 500 itself, since Starlette routes it to the outermost `ServerErrorMiddleware`, above the header middleware. Local to the one response class that escapes.

- **Subsystem:** HTTP/errors · **Invariant:** docs/05 transport hardening · **File:** `http/errors.py:148`

Starlette routes the `Exception` handler (`_unhandled`) to the OUTERMOST `ServerErrorMiddleware`, outside `_headers`. An exception with no registered handler (raw `psycopg.Error` — none is registered — or `TypeError`) propagates through `_headers`/`_blanket` (which never catch) to `ServerErrorMiddleware`, whose 500 ships with NO CSP/nosniff/Referrer-Policy/Cache-Control/Permissions-Policy. The `_unhandled` comment claiming to fix this only fixes the body. 400/403/409/422/429 are unaffected. Low — fixed problem+json body, no reflected content.

**Fix:** Stamp `_SECURITY_HEADERS` in `_unhandled`, or move header-stamping into a pure ASGI middleware wrapping `send()`.

## CR18 — LOW — Search pane `Promise.all` blanks the whole pane on one sub-request failure

> **✅ FIXED (2026-07-26).** `runSearch` uses `Promise.allSettled` and renders each column independently, reporting a per-column problem instead of blanking both.

- **Subsystem:** UI · **File:** `http/static/app.js:2599`

`runSearch` awaits `Promise.all([search/nodes, search/evidence])` with a single catch that clears both boxes. The scopes differ (`case.read` vs `evidence.read`) but every seeded role holding one holds the other, so the permission-split isn't reachable without a custom admin role — the real triggers are a 429 when the two parallel calls race the same `rate_limit('search')` meter, or a 500 on the evidence query. Pure availability/UX; nothing leaks. The team already fixed this pattern for Sources via `section()`.

**Fix:** `Promise.allSettled` or per-column try/catch.

## CP1 — LOW (PLAUSIBLE) — Billion-laughs DTD bypasses `parse_rss` byte window

> **✅ FIXED (2026-07-26).** `parse_rss` scans to `_root_element_offset(body)` — the first element start-tag — rather than a fixed 8 KiB window, capped at 1 MiB. Proven: a DTD behind 9 KB of comment is now refused, and a clean feed with the same padding still parses.

- **Subsystem:** collection (Phase 4) · **File:** `collection.py:603`

`parse_rss` scans only `body[:8192]` for `<!DOCTYPE`/`<!ENTITY` while bodies up to 16 MiB are accepted, so a >8 KB comment before the DTD evades the regex — **confirmed**. But the harm is not demonstrable from the code: ElementTree resolves no external entities (no XXE file-read), and Python 3.12's libexpat >=2.4 enables billion-laughs amplification limits by default (surfaces as a caught `ParseError`). Defence-in-depth gap, exploit depends on deployed libexpat.

**Fix:** Scan the whole prolog, or use a hardened `XMLParser`/`defusedxml` rather than a byte-window regex.

## CX1 — REFUTED — Element-level 403-vs-404 existence oracle (`http/deps.py`)

The 403/404 mechanism is real but the finding misattributes the invariant: the cited `user_ceiling` rule governs SEARCH-RESULT filtering, which still hides over-classified elements from discovery. The direct GET-by-id 403 is documented intentional behavior (`deps.py:174-176`) and only concerns unguessable UUIDs the caller already held while cleared — no discovery of new elements. Negligible; invariant upheld.

## CX2 — REFUTED — SAME_AS edge permits IDENTITY/PERSON crossing (`0017_seed_ontology.py`)

The finder read only the `0016` trigger function and missed **`0018_selector_hardening.py`**, which `CREATE OR REPLACE`s it to add `IF NEW.edge_type='SAME_AS' AND src_ty<>dst_ty THEN RAISE`. The `edge_validate` trigger binds by name, so a cross-layer SAME_AS insert raises, rolls back, and returns 400. Invariant 2 holds; the premise is stale.

## Code-review themes and bottom line

1. **Read paths hardened, write/generate/destroy paths not (CR1, CR5, CR7, CR11).** The dominant class — the one worth fixing as a class: every mutate/generate/destroy handler must authorize against the effective (element-or-target) labels using the caller's OWN ceiling, the way the read handlers already do.
2. **Bidi/zero-width visual spoofing (CR4, CR13, CR14):** the `withSafeLabel`/`visibleText` defence exists but is not applied at every render/parse site. Best fixed at the API-landing choke point.
3. **Append-only ledgers missing the TRUNCATE guard (CR15, CR16).**
4. **Single-node / NaN correctness pair (CR8, CR9).**

The core invariant machinery is sound (assertion triggers, five-part gate structure, auth/crypto, evidence WORM/custody all survived; two slices returned nothing). The confirmed defects are localized, at the edges. **CR1 is a genuine confidentiality breach and should be fixed first.** This is a code-quality assessment only; it says nothing about the four BLOCKING legal items (docs/16, docs/18), which gate operation regardless of code quality.
