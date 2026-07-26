# TestFlight — installing the packaged release, step by step

**Date:** 2026-07-26
**Artefact tested:** `NocTORnal - Alpha Release`, produced by
`scripts/package_release.ps1` from commit `HEAD` of
`deception-and-release-hardening`.
**Host:** Windows 11 Pro 26200, PowerShell 5.1, Python 3.13, Docker
Desktop with Compose v2.

**Result: PASS.** Clean install from the packaged directory, all 52
migrations against an empty database, **1269 tests passing, 0 skipped**,
API serving, UI rendering, all sixteen panes.

> **Three real defects were found by doing this**, none of which 1257
> passing tests on the development machine could have caught. They are in
> §6 and all three are fixed and re-verified.

---

## 0) Why this document exists

The release review's closing line was that *"the installers and the
sample-storage path have never run end-to-end on a machine that was not
already set up — 1206 green tests, none of which runs the installer."*

This is that exercise. Every command below was actually run, in this
order, and the output quoted is the output received.

---

## 1) Produce the package

From the source tree:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package_release.ps1 `
    -Destination "C:\Users\you\Desktop\NocTORnal - Alpha Release" -Force
```

`git archive` exports the **commit**, not the working directory, so
`.env.local`, `.venv`, `.git`, `screenshots/` and `shots/` cannot be
included. The script then asserts their absence and refuses to finish if
any appear:

```
  Packaging HEAD
    wrote ...\NocTORnal - Alpha Release
  Verifying the package
    no .env.local, no .venv, no .git, no screenshots
    installers, alembic.ini, compose file and LICENSE all present
    install.sh is LF
    install.ps1 parses
    install.sh parses
```

The last two lines exist because an earlier run of this exercise shipped
an `install.ps1` that did not parse (§6.2).

**Package contents:** 52 migrations, 56 test files, 16 screenshots,
5.7 MB. Standalone — `release/` sits *inside* the tree, so the installers
resolve the project as their own parent and reference nothing adjacent.

---

## 2) Install, from the package directory only

```powershell
cd "C:\Users\you\Desktop\NocTORnal - Alpha Release"
powershell -ExecutionPolicy Bypass -File .\release\install.ps1 -SkipLaunch
```

`-SkipLaunch` was used **only** so the verification below could point at a
throwaway database instead of the developer's. A recipient omits it and
gets steps 3–5 automatically.

```
  Locating the application
    found at C:\Users\you\Desktop\NocTORnal - Alpha Release
  Checking Python
    Python 3.13 at C:\...\python.exe
  Checking Docker
    Docker engine is running
  Building the Python environment
    creating .venv (this takes a moment)
    created
    installing dependencies
    dependencies installed (with dev extras)
  Generating secrets
    wrote .env.local with fresh random keys
```

Checks made at this point:

| | |
|---|---|
| the project resolved to the package's **own** parent | ✅ no sibling probing |
| `alembic` present in the new venv | ✅ `alembic 1.18.5` |
| `python-multipart` present | ✅ `0.0.32` — see §6.1 |
| `.env.local` has **no BOM** | ✅ first bytes `23 20 47 65` (`# Ge`) — see §6.3 |
| `.env.local` sources in bash | ✅ `set -a; . ./.env.local; set +a` silent |

---

## 3) A database, from empty

The packaged compose file is the same one the source tree uses, so
`docker compose up -d` reuses a running stack rather than starting a
second. For an honest from-scratch migration test a separate database was
created **using the project's own extension script** — not a hand-written
guess (the first attempt guessed, omitted `citext`, and died at migration
0012; that was a flaw in the test, not the product, because a real
recipient gets `noctornal` created by `POSTGRES_DB` with
`/docker-entrypoint-initdb.d` applied):

```bash
docker exec -i noctornal-postgres-1 psql -U noctornal -d postgres \
  -c "CREATE DATABASE noctornal_alpha OWNER noctornal;"
docker exec -i noctornal-postgres-1 psql -U noctornal -d noctornal_alpha \
  < db/init/00-extensions.sql
```

Then, from the package:

```bash
export DATABASE_URL="postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal_alpha"
./.venv/Scripts/python.exe -m alembic upgrade head
./.venv/Scripts/python.exe -m alembic current      # -> 0052 (head)
```

**All 52 migrations applied to an empty database.** ✅

---

## 4) First account

```bash
set -a && . ./.env.local && set +a
./.venv/Scripts/python.exe scripts/bootstrap.py create-user \
    --email analyst@alpha.test --name "Alpha Tester"
```

Printed the generated password once, the base32 TOTP secret, the
`otpauth://` URI and a scannable ASCII QR. Clearance RED, roles
`CASE_OWNER, SYS_ADMIN`.

Note this ran in a shell with **no exports beyond `DATABASE_URL`** —
`bootstrap.py` reads `.env.local` itself. That is release finding R9, and
this is the check that it holds.

---

## 5) Verify

### The suite, from the package

```bash
DATABASE_URL="postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal_alpha" \
MINIO_ENDPOINT=localhost:9000 MINIO_ACCESS_KEY=noctornal \
MINIO_SECRET_KEY=dev_only_change_me EVIDENCE_BUCKET=noctornal-evidence \
SAMPLE_BUCKET=noctornal-samples REDIS_URL=redis://localhost:6379/0 \
  ./.venv/Scripts/python.exe -m pytest apps/api/tests packages/ontology -q
```

```
1269 passed, 1 warning in 188.51s (0:03:08)
```

**1269 passed, 0 skipped.** Higher than the 1257 quoted for the source
tree because `REDIS_URL` was set here, so the Redis rate-limiter leg runs
instead of skipping. The single warning is an upstream Starlette
deprecation notice about `httpx`.

### The API

```bash
./.venv/Scripts/python.exe -m uvicorn noctornal_api.http.app:create_app \
    --factory --host 127.0.0.1 --port 8000 --app-dir apps/api/src
```

| Check | Result |
|---|---|
| `GET /healthz` | `200` |
| `GET /ui/` | `200` |
| `GET /ui/app.js` | `200` |
| `GET /api/v1/cases` unauthenticated | `401` — gated |
| `GET /api/v1/cases/{id}/deception/captures` | `401` — route registered, gate ran |
| Security headers on every response | `nosniff`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Permissions-Policy` |

### The UI

Seeded a case and the deception demo, then rendered every pane headless:

```bash
./.venv/Scripts/python.exe scripts/bootstrap.py demo-network \
    --owner-email analyst@alpha.test --code OP-ALPHA-VERIFY
./.venv/Scripts/python.exe scripts/seed_deception_demo.py --case OP-ALPHA-VERIFY
./.venv/Scripts/python.exe scripts/screenshot_ui.py \
    --email analyst@alpha.test --case OP-ALPHA-VERIFY --out <outside-the-repo>
```

**16/16 panes captured.** The Deception pane was read directly: defanged
non-clickable URL, `live` chip, TLP badge, TLS key, redirect target — all
correct.

---

## 6) What this exercise found

Three defects. **None was reachable from the development machine**, which
is the entire point of doing it.

### 6.1 `python-multipart` was not a declared dependency · BLOCKER

FastAPI needs it for **every** `Form(...)` and `UploadFile` parameter and
does not depend on it. The first run of the suite in the fresh venv gave
**117 errors**:

```
RuntimeError: Form data requires "python-multipart" to be installed.
```

`pip show python-multipart` on the development machine reports an **empty
`Required-by`** — it was hand-installed there long ago, so every test
passed locally forever.

This is release finding R3's shape and worse. R3 (`alembic`) failed loudly
*at install time*. This one installs cleanly, passes every test that does
not touch a multipart route, and then fails the first time an analyst
uploads an exhibit, a malware sample or a `.eml` — the three routes the
product exists for.

**Fixed:** declared in `apps/api/pyproject.toml`.

### 6.2 The packaged `install.ps1` did not parse · BLOCKER

An editing pass put a literal newline inside a PowerShell comment, so the
continuation line stopped being a comment and PowerShell tried to run it:

```
install.ps1 : The term 'to' is not recognized as the name of a cmdlet
```

The package had already been built and "verified" — because every check
was a static read and nothing executed the artefact.

**Fixed**, and `package_release.ps1` now parses `install.ps1` with the
PowerShell AST parser and runs `bash -n` over `install.sh` before it will
report success. A syntax check is free; a recipient discovering it is not.

### 6.3 `.env.local` was written with a BOM · HIGH

PowerShell 5.1's `Set-Content -Encoding UTF8` writes a byte order mark.
`install.sh` sources that file with `set -a; . "$ENV_LOCAL"`, and bash
does not strip a BOM:

```
./.env.local: line 1: $'\357\273\277#': command not found
./.env.local: line 1: never: command not found
```

`bootstrap.py`'s own loader survived **only by luck** — line 1 of the
generated file happens to be a comment. Had a KEY been first, that key
would have been silently mis-named, presenting as *"the KEK is not set"*
with the KEK plainly sitting in the file.

**Fixed** at the writer (`-Encoding ascii`; every byte written is a base64
secret, a URL or a port) and at both readers (`utf-8-sig`, identical to
`utf-8` when there is no BOM) — because a file edited in Notepad will have
one whatever the installer does.

---

## 6a) The zip

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package_release.ps1 -Zip
```

Produces `NocTORnal - Alpha Release.zip` — **2.5 MB, 294 entries**,
verified from outside PowerShell (which is the only place the questions
below can be answered honestly):

| | |
|---|---|
| CRC integrity | OK, every entry |
| Top-level entries | exactly one: `NocTORnal - Alpha Release/` |
| Path separators | 294 forward slashes, 0 backslashes |
| Secrets | no `.env.local`, no `.venv/`, no `.git/` |
| `install.sh` | 0 CRLF, shebang intact through the archive |
| Extraction | 294 files, installer resolves the project from inside the tree, both installers parse |

Three things this got wrong before it got right, all worth knowing:

- **The first zip had no wrapper directory.** `Compress-Archive -Path
  "$dir\*"` archives the CONTENTS, so unzipping scattered twenty-two
  top-level entries loose into the recipient's Downloads folder.
- **The check written to catch that then failed a good archive.** It split
  entry names on `/`, but .NET's `ZipArchiveEntry.FullName` reports the
  PLATFORM separator, so all 294 entries looked like a single
  294-segment root. The stored bytes were correct the whole time.
- **Which also means PowerShell cannot answer the separator question at
  all.** `ZipFile.CreateFromDirectory` is used instead of
  `Compress-Archive` partly because it writes spec-compliant forward
  slashes; confirming that needs a tool outside .NET, and the command to
  do it is in the script's comment.

### One Windows constraint worth stating

Windows' 260-character `MAX_PATH` still applies to extraction. The
archive's longest entry is 89 characters:

```
NocTORnal - Alpha Release/db/migrations/versions/0036_renormalise_comms_durable_values.py
```

So extraction fails if the destination path exceeds roughly 170
characters. A Downloads or Desktop folder is nowhere near that — the
first extraction attempt here failed only because the scratchpad used for
testing has a 178-character base path, which is not a real-world
location. Extracting to `%TEMP%
zt` (37 characters) succeeded with all
294 files.

---

## 7) Re-running this

```powershell
# 1. package
powershell -ExecutionPolicy Bypass -File .\scripts\package_release.ps1 -Force

# 2. install, from the package
cd "..\NocTORnal - Alpha Release"
powershell -ExecutionPolicy Bypass -File .\release\install.ps1

# 3. that is it — the installer starts the stack, migrates, offers to
#    create an account and opens the console.
```

To repeat the *verification* rather than the install, use `-SkipLaunch`
and follow §3–§5.

### What is still untested

Stated plainly, because a test report that claims more than it did is
worse than none:

- **A genuinely clean machine.** This host already had Docker images
  pulled, Python installed and the compose stack running. The Python and
  Docker *detection* paths were exercised; the "install Docker Desktop
  first" path was not.
- **`install.sh` on Linux or macOS.** It correctly refuses to run under
  Git Bash on Windows (a Unix-layout venv there would be broken), so it
  could not be exercised here. Its syntax is checked by `bash -n` in the
  packager, and the R4/R9/R11/R17 fixes in it are reviewed but not run.
- **Python 3.12.** Supported and accepted by the installers; only 3.13
  has actually run this code (release finding R15).
- **A real TOTP login through a browser.** The `session` bypass was used.
  Step-up-gated actions — merge, export, purge, sample download — remain
  refused until a real TOTP login exists, by design.
- **A real sample upload to MinIO.** The bucket is now created (R10) and
  was confirmed present, but Phase 8 ingest refuses until the L1
  prohibited-content policy is declared, and declaring one to make a test
  pass would be exactly the false declaration the README warns about.
