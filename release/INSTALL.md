# Installing NocTORnal

> **Read [README.md](README.md) first.** Four legal decisions gate any use
> of this software against real material. Installing it is fine; pointing
> it at a real case is not, until those are settled.

---

## The short version

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy Bypass -File .\release\install.ps1
```

**macOS / Linux:**

```bash
chmod +x release/install.sh && ./release/install.sh
```

Neither prefix is decoration (R6). The default Windows client
ExecutionPolicy is `Restricted`, and a file extracted from a downloaded
zip additionally carries Mark-of-the-Web — bare `.\install.ps1` is
blocked either way. A `.sh` out of a zip has no execute bit, so `./` fails
with "permission denied" before bash ever sees it.

That is the whole thing. It checks what it needs, installs what is
missing that it can install, starts the services, creates the database,
makes you an account, and opens the console.

Re-running it is safe. Every step checks before it acts and reports what
it found.

---

## What you need first

The installer checks all of these and tells you exactly what to do if one
is missing, rather than failing halfway.

| | Version | Why |
|---|---|---|
| **Python** | 3.12 or newer | The API and workers |
| **Docker** | any recent version, with Compose v2 | Four containers: Postgres, Redis, MinIO, Mailpit. Budget ~3 GB RAM for them. |
| **~4 GB RAM free** | | Postgres and MinIO are the hungry ones |
| **~2 GB disk** | | Containers, the virtual environment and the database |

Optional, and only for the features that use them:

| | For |
|---|---|
| **GnuPG** on `PATH` | Verifying PGP-signed vendor messages (Comms). Without it, verification returns "no verifier" rather than silently claiming a signature is good. |
| **Google Chrome** | `scripts/screenshot_ui.py`, a development tool |

---

## What the installer actually does

Nothing hidden, in this order:

1. **Checks Python and Docker.** Stops with a specific instruction if
   either is missing or too old.
2. **Creates a virtual environment** at `.venv` and installs the API and
   the ontology package into it.
3. **Generates secrets** into `.env.local` — a TOTP key-encryption key and
   an ingest pepper, both random, both 32 bytes. *It never writes a default
   secret.* If the file already exists it is left alone.
4. **Starts the containers** and waits for Postgres to report healthy.
5. **Applies the database migrations** (`alembic upgrade head`).
6. **Creates your account** if no user exists, and prints the enrolment QR
   for your authenticator.

   > **Windows note (R8).** `install.ps1` hands off to `launch.ps1`, which
   > prints a banner telling you to run `create-user` in a second terminal
   > — and then starts uvicorn, whose log scrolls that banner off the
   > screen within seconds. If you reach the sign-in page with no
   > credentials, that is why. Run:
   >
   > ```powershell
   > .venv\Scripts\python scriptsootstrap.py create-user --email you@example.org --name "Your Name"
   > ```
   >
   > It works in a fresh terminal with no exports: `bootstrap.py` reads
   > `.env.local` itself.

7. **Starts the API** and prints the console URL.

Every one of those is idempotent. Stopping it half way and running it
again does the right thing.

---

## Signing in

Open <http://127.0.0.1:8000/ui/>.

The first account is created for you during install, with a TOTP secret
you scan into an authenticator app.

### If TOTP will not accept your code

TOTP is a function of **absolute time**, so it fails on a machine whose
clock is wrong — and it fails in a way that looks like a bad secret. Check
the clock before debugging anything else.

For a machine whose clock cannot be fixed, there is an explicit bypass:

```bash
.venv/bin/python scripts/bootstrap.py session --email you@example.com
# Windows:  .venv\Scripts\python scriptsootstrap.py session --email you@example.com
```

It prints a URL carrying a session token. **It is recorded in the audit
trail as an MFA-bypassed login**, deliberately — it exists to get you
working on a broken host, not as the normal way in.

---

## Turning it off and on

```bash
# stop the API:            Ctrl-C in its window
# stop the containers:
docker compose -f infra/docker-compose.yml down

# start everything again:
./release/install.sh          # or: powershell -ExecutionPolicy Bypass -File .\release\install.ps1
```

Data lives in Docker volumes and survives `down`. To destroy it
completely, add `-v` — which deletes every case, exhibit and audit row,
irreversibly.

---

## Configuration

Settings come from the environment or `.env.local`. **Nothing has a
default secret**; a missing value produces a deliberate, explained refusal
rather than an insecure fallback.

The ones worth knowing:

| Variable | Effect if unset |
|---|---|
| `NOCTORNAL_TOTP_KEK` | The API will not start. Generated for you at install. |
| `NOCTORNAL_INGEST_PEPPER` | Ingest keys cannot be issued. Generated for you. |
| `NOCTORNAL_PROHIBITED_CONTENT_POLICY`<br>`NOCTORNAL_DESIGNATED_PERSON` | **Sample ingest returns 451.** This is L1, and the refusal is the point. Set both only once counsel has written the policy. |
| `NOCTORNAL_SAMPLE_ORIGIN` | Sample downloads are refused. Invariant 10 requires malware bytes to come from a **separate origin**; an origin split that is only written down does not survive the first hurried deploy. |
| `NOCTORNAL_NOTIFY_ADDRESS_DOMAINS` | Analysts cannot redirect their own notification email at all. Fail-closed on purpose: a subject line carries a case code, and a case code is intelligence. |
| `NOCTORNAL_LIVE` | Live updates are on. Set to `0` behind PgBouncer in transaction mode, where `LISTEN` cannot work. |
| `REDIS_URL` | Rate limiting falls back to per-process, and says so loudly at startup. |
| `NOCTORNAL_ENABLE_DOCS` | The OpenAPI schema stays off. It publishes the full route inventory of a law-enforcement case system, so it is opt-in. |

---

## Troubleshooting

**"port 8000 is already in use"** — an earlier copy of the API is still
running. Stop it, or pass `-Port 8001` / `--port 8001`.

**"No 'script_location' key found in configuration"** — you ran `alembic`
from `db/`. It must run from the repository root, where `alembic.ini`
lives. This reads as a broken install and is not one.

**A new route returns 404 after you changed the code** — the API runs
without `--reload`. Static files (the UI) are served from disk and update
immediately; Python does not. Restart it.

**The graph does not update when a colleague writes** — check the dot in
the header. Grey means the live channel is not connected, and the console
falls back to manual refresh. That is a convenience feature, not a
correctness one; nothing is lost.

**PGP tests fail rather than skip** — that is deliberate. The only
cryptographic-evidence path in the system should break the build if it
goes untested. Put `gpg` on `PATH`.

---

## Verifying the install

```bash
# macOS / Linux
DATABASE_URL="postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal"   .venv/bin/python -m pytest apps/api/tests packages/ontology -q
```

```powershell
# Windows
$env:DATABASE_URL = "postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal"
.venv\Scripts\python -m pytest apps/api/tests packages/ontology -q
```

Expect **1252 passed, 12 skipped**.

**That number has preconditions, and without them you will see something
very different (R7):**

| | |
|---|---|
| the containers are **up** | `docker compose -f infra/docker-compose.yml ps` |
| `DATABASE_URL` is **exported in this shell** | the installers persist it to `.env.local`, but pytest does not read that file — hence the explicit assignment above |
| both directories are given | the suite spans two pytest roots; running one gives a number that matches nothing in the documentation |

**Without `DATABASE_URL` you will see roughly 700 skips**, because 37 test
files are `skipif`-gated on it. That is a correct result and not a broken
install — the core of the suite is deliberately database-free so it can
run anywhere.

The 12 remaining skips are optional-dependency paths. If `gpg` is not on
your `PATH` you will additionally see PGP failures rather than skips:
`test_pgp.py` asserts the binary is present deliberately, so a missing
verifier is loud rather than silent. INSTALL lists GnuPG as optional for
*operating* the product, which is true; it is not optional for running
the full suite green.

> Running the suite **with** `DATABASE_URL` set writes permanent rows into
> the append-only tables (`audit.event`, custody ledgers) of the database
> you point it at. That is by design — those tables refuse deletion — but
> it is startling on a fresh install, and it is a reason not to point the
> test suite at anything you care about.
