# Installing NocTORnal

> **Read the [five blocking items](../README.md#five-blocking-items-none-of-them-a-software-problem)
> in the README first.** Five legal decisions, L1 to L5, gate any use of
> this software against real material. Installing it is fine; pointing it
> at a real case is not, until those are settled.

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
zip additionally carries Mark-of-the-Web; bare `.\install.ps1` is
blocked either way. A `.sh` out of a zip has no execute bit, so `./` fails
with "permission denied" before bash ever sees it.

That is the whole thing. It checks what it needs, installs the Python
packages into a virtual environment of its own, starts the services,
creates the database, makes you an account (on Windows it prints the
command that does, see step 6 below), starts the API and prints the
console URL. It does not open a browser.

Re-running it is safe. Every step checks before it acts and reports what
it found.

---

## What you need first

The installer checks Python and Docker and tells you exactly what to do
if either is missing, rather than failing halfway. Memory and disk are
not checked; the figures below were measured on a clean Ubuntu 24.04
machine with 8 GB of RAM.

| | Minimum | Notes |
|---|---|---|
| **Python** | 3.12 | With `venv` and `ensurepip`. On Debian and Ubuntu those are a separate package: `sudo apt update && sudo apt install python3.12-venv`. 3.13 is what it is developed on. |
| **Docker** | with Compose v2 | Docker Engine and its Compose plugin on Linux; Docker Desktop on Windows and macOS. Runs four containers: Postgres, Redis, MinIO, Mailpit. |
| **Memory** | 8 GB tested | The four containers used about 300 MB at idle after the showcase seed. Postgres is configured with `shared_buffers=512MB`, so it grows past that under load. |
| **Disk** | 2 GB free | 1.4 GB was added by the install and the showcase seed: 1.1 GB of images, a 189 MB `.venv`, and the data. Installing Docker Engine on a bare Ubuntu took about 0.75 GB before that. |
| **OS** | Windows 10/11, macOS 12+, Linux | PowerShell 5.1 is supported and specifically tested for. |

Optional, and only for the features that use them:

| | For |
|---|---|
| **GnuPG** on `PATH` | Verifying PGP-signed vendor messages (Comms). Without it, verification returns "no verifier" rather than silently claiming a signature is good. |
| **Node.js** on `PATH` | The test suite's browser-side checks of the console. Without it they skip; the static checks still run. |
| **Google Chrome** | `scripts/screenshot_ui.py`, a development tool |

---

## What the installer actually does

Nothing hidden, in this order:

1. **Checks Python and Docker.** Stops with a specific instruction if
   either is missing or too old, if Python cannot build a virtual
   environment, or if the Docker engine is not reachable.
2. **Creates a virtual environment** at `.venv` and installs the API and
   the ontology package into it.
3. **Generates secrets** into `.env.local`, a TOTP key-encryption key and
   an ingest pepper, both random, both 32 bytes. *It never writes a default
   secret.* Beside them it writes the development stack's settings, and
   names each service by `127.0.0.1` rather than `localhost`
   (`DATABASE_URL`, `REDIS_URL`, `MINIO_ENDPOINT`, `SMTP_HOST`). If the
   file already exists it is left alone.
4. **Starts the containers** and waits for Postgres to report healthy.
5. **Applies the database migrations** (`alembic upgrade head`).
6. **Creates your account** if no user exists, and prints the password
   once with the enrolment QR for your authenticator.

   > **Windows note (R8).** `install.ps1` hands off to `launch.ps1`, which
   > prints a banner telling you to run `create-user` in a second terminal,
   > and then starts uvicorn, whose log scrolls that banner off the
   > screen within seconds. If you reach the sign-in page with no
   > credentials, that is why. Run:
   >
   > ```powershell
   > .venv\Scripts\python scripts\bootstrap.py create-user --email you@example.org --name "Your Name"
   > ```
   >
   > It works in a fresh terminal with no exports: `bootstrap.py` reads
   > `.env.local` itself.

7. **Starts the API** on 127.0.0.1 and prints the console URL. If the
   port is already taken it stops and says so instead (see
   Troubleshooting).

Every one of those is idempotent. Stopping it half way and running it
again does the right thing.

The bundled services (Postgres on 5432, Redis on 6379, MinIO on 9000 and
its console on 9001, Mailpit on 1025 and 8025) are
published on 127.0.0.1 only, so other machines cannot reach them. They
run with the development credentials that are written in this
repository, and on Linux a port Docker publishes on every interface is
reachable from the network even with ufw denying incoming traffic,
because Docker's forwarding rules are applied before ufw's. So do not
change them to `0.0.0.0` in `infra/docker-compose.yml`: a host firewall
would not close them again. To reach the MinIO console or Mailpit from
another machine, use an SSH tunnel, for example
`ssh -L 9001:127.0.0.1:9001 you@the-host`.

A stack started by an earlier release keeps its old bindings, on every
interface, until its containers are recreated from this file.
`docker compose -f infra/docker-compose.yml up -d` does that and keeps the
data volumes; re-running the installer runs it too.

---

## After installing

### Signing in

Open <http://127.0.0.1:8000/ui/> and sign in with the account the
installer created, using the password it printed once and a code from the
authenticator you scanned its QR into.

Commands in this section run from the repository root in a second
terminal, which needs no exports: `bootstrap.py` reads `.env.local`. On
Windows the interpreter is `.venv\Scripts\python` and the script is
`scripts\bootstrap.py`.

To fill the console with the showcase case the README's screenshots come
from, follow **[First run](../README.md#first-run)** in the README, with
the address you gave the installer as `--owner-email`.

### Nobody holds the Security Officer role yet

The installer's account holds two global roles, Lead investigator
(`CASE_OWNER`) and `SYS_ADMIN`. It does not hold `SECURITY_OFFICER`, and
nothing else on a fresh install does. The readiness register (the Admin
pane in the console, or `GET /api/v1/admin/readiness`) therefore reports
`security_officer_present` as failing, and that is one of its four
blocking checks:

- collection runs are refused until it passes;
- break-glass is refused, because nobody could review it;
- `audit.read` is held by this role alone, so nobody can read the audit
  trail.

Give the role to a second person. Not to your own account: the officer
reviews your break-glass and authorises the victim-PII reveals and
preserved-sample retrievals that a Lead investigator asks for, and the
software refuses the same person on both sides of each.

```bash
.venv/bin/python scripts/bootstrap.py create-user \
    --email security.officer@example.org --name "Officer Name" --roles SECURITY_OFFICER
```

It prints that person's password once, with the QR for their
authenticator, and they choose their own password at their first
sign-in. To give the role to a colleague who already has an
account, use **Grant role** on their card in the Admin pane instead.

The README's showcase seeder also adds an officer account,
`officer@example.org`, which is why the example above uses a different
address. It is fictional and its password is never shown, so nobody
signs in as it through the console. It turns the check green on a
demonstration install; it is not a second person. Anyone with a shell on
the host and its `.env.local` can still mint a session for it with
`bootstrap.py session --email`, as for any account, which is one more
reason a demonstration install is not a deployment.

The other three blocking checks on a fresh install
(`prohibited_content_policy`, `sample_origin_configured` and
`retention_rules_confirmed`) are declarations the deployment has to make,
and the register names what each needs.

The register wants a recent sign-in. It sits behind `user.manage`, a
step-up permission, so it answers only a session whose second factor is
less than 15 minutes old. An older session gets 403 "re-authentication
required" while the rest of the console still works, and that includes
the link `bootstrap.py session` prints, 15 minutes after it was made.
Sign out and back in with your password and an authenticator code, or
mint a new link, and read the register within the next 15 minutes.

### Checking the preservation bucket

A rejected sample is preserved in the `noctornal-preserved` bucket under
a legal hold. That bucket has object lock enabled and, by design, no
default retention, and `mc` misreports it: `mc retention info --default`
prints "Object locking is not enabled." and a plain `mc stat` shows no
lock configuration, although `mc stat --json` does report it, as
`"ObjectLock":{"enabled":"Enabled"}`. The readiness register's
`preservation_bucket_object_lock` check is the better witness, because it
proves the lock rather than reading it: it writes canary objects into the
bucket and passes only when a DELETE naming a locked or held version is
refused.

### If TOTP will not accept your code

TOTP is a function of **absolute time**, so it fails on a machine whose
clock is wrong, and it fails in a way that looks like a bad secret. Check
the clock before debugging anything else.

For a machine whose clock cannot be fixed, there is an explicit bypass:

```bash
.venv/bin/python scripts/bootstrap.py session --email you@example.com
# Windows:  .venv\Scripts\python scripts\bootstrap.py session --email you@example.com
```

It prints a URL carrying a session token. **It is recorded in the audit
trail as an MFA-bypassed login**, deliberately. It exists to get you
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
completely, add `-v`, which deletes every case, exhibit and audit row,
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
| `NOCTORNAL_LIVE_MAX_SOCKETS` | 200 authenticated live subscribers per API process; the next is refused with close code 1013. |
| `NOCTORNAL_LIVE_MAX_PENDING` | A quarter of the subscriber ceiling (50 by default) of sockets that are open but not yet authenticated, per process. A peer with no session pays for these, so the budget is small, and a full budget is refused before the WebSocket handshake completes so that a refused socket holds nothing. |
| `NOCTORNAL_LIVE_MAX_PENDING_PER_PEER` | 8 of those per peer address, the same address the rate limiter uses, trusted proxy hops included. |
| `NOCTORNAL_LIVE_HELLO_SECONDS` | 10 seconds for an accepted socket to send its hello before it is closed and its slot returned. |
| `REDIS_URL` | Rate limiting falls back to per-process, and says so loudly at startup. |
| `NOCTORNAL_ENABLE_DOCS` | The OpenAPI schema stays off. It publishes the full route inventory of a law-enforcement case system, so it is opt-in. |

---

## Troubleshooting

**"port 8000 is already in use"**: an earlier copy of the API is still
running, or something else holds the port. Both installers stop with this
before starting the API. If it is an earlier copy, the stack is already
up at <http://127.0.0.1:8000/ui/>. Otherwise stop what holds the port, or
pass `--port 8001` (`-Port 8001` on Windows).

**"No 'script_location' key found in configuration"**: you ran `alembic`
from `db/`. It must run from the repository root, where `alembic.ini`
lives. This reads as a broken install and is not one.

**`alembic` stops with "DATABASE_URL is not set or is empty"** in a new
terminal: unlike `bootstrap.py`, Alembic reads the environment only, and
it does not guess a target. Load `.env.local` first
(`set -a; . ./.env.local; set +a`, or the PowerShell line under
Verifying the install).

**A new route returns 404 after you changed the code**: the API runs
without `--reload`. Static files (the UI) are served from disk and update
immediately; Python does not. Restart it.

**The graph does not update when a colleague writes**: check the dot in
the header. Grey means the live channel is not connected, and the console
falls back to manual refresh. That is a convenience feature, not a
correctness one; nothing is lost.

**Redis logs "WARNING Memory overcommit must be enabled!"** on every
start: that is Redis's standard advice to set `vm.overcommit_memory=1` on
the host. It is harmless for an evaluation install; set the sysctl on a
host that keeps the stack running long term.

**Mailpit logs "the API is reachable from any host that can route to this
interface"** on every start: that describes the network inside the
stack, where Mailpit listens on every interface of its own container. On
the host its ports are published on 127.0.0.1 only, and on a clean Linux
install they were refused on the machine's external address, from a
separate network namespace as well as from the host itself.

**`minio-init` exited 1**: it creates the buckets, after waiting about
two minutes for MinIO to accept the development credentials. If MinIO
never does, it prints MinIO's own error once, exits 1, and the buckets
are not made. `docker compose -f infra/docker-compose.yml ps -a` shows its
exit code and `docker compose -f infra/docker-compose.yml logs minio-init`
the error. A clean start's log has no ERROR line in it.

**On Windows, every connection to Postgres or MinIO takes about two
seconds**: the `.env.local` was written by an earlier installer, which
named the services `localhost`. With Windows' default address
preferences `localhost` resolves to `::1` first, nothing listens there
now that the services are published on 127.0.0.1 only, and a refused
connection on Windows takes about two seconds before the client tries
127.0.0.1. Replace `localhost` with `127.0.0.1` in `DATABASE_URL`,
`REDIS_URL`, `MINIO_ENDPOINT` and `SMTP_HOST` in `.env.local`, which is
what a new one carries. On Linux the old file works as it is: there
`localhost` reached every service in a millisecond or less.

**PGP tests fail rather than skip**: that is deliberate. The only
cryptographic-evidence path in the system should break the build if it
goes untested. Put `gpg` on `PATH`.

---

## Verifying the install

Run the suite against a scratch database, never against one that holds
anything you want to keep. With `DATABASE_URL` set, it changes the
database it names for good: it writes permanent rows into the
append-only tables (`audit.event`, custody ledgers), which refuse
deletion by design, and some tests run real migrations against it
(`test_compartment_binding_pg.py` downgrades it to `0058` and upgrades it
back to head). The `DATABASE_URL` in `.env.local` names the install's own
database, so the commands below make a scratch one beside it, the way CI
does, and point the suite there.

Load `.env.local` into the shell first, from the repository root. It
carries `DATABASE_URL`, `REDIS_URL` and the MinIO and Mailpit settings,
and pytest does not read the file itself.

```bash
# macOS / Linux
set -a; . ./.env.local; set +a
docker compose -f infra/docker-compose.yml exec -T postgres createdb -U noctornal noctornal_scratch
docker compose -f infra/docker-compose.yml exec -T postgres psql -U noctornal -d noctornal_scratch -q -f /docker-entrypoint-initdb.d/00-extensions.sql
export DATABASE_URL=postgresql+psycopg://noctornal:dev_only_change_me@127.0.0.1:5432/noctornal_scratch
.venv/bin/alembic upgrade head
.venv/bin/python -m pytest apps/api/tests packages/ontology -q
```

```powershell
# Windows
Get-Content .env.local | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*=' } | ForEach-Object { $k, $v = $_ -split '=', 2; Set-Item "env:$k" $v }
docker compose -f infra/docker-compose.yml exec -T postgres createdb -U noctornal noctornal_scratch
docker compose -f infra/docker-compose.yml exec -T postgres psql -U noctornal -d noctornal_scratch -q -f /docker-entrypoint-initdb.d/00-extensions.sql
$env:DATABASE_URL = 'postgresql+psycopg://noctornal:dev_only_change_me@127.0.0.1:5432/noctornal_scratch'
.venv\Scripts\alembic upgrade head
.venv\Scripts\python -m pytest apps/api/tests packages/ontology -q
```

The third command loads the extensions the schema needs, which only a
superuser can create; in the development stack `noctornal` is one. To
start again from nothing, drop the scratch database with
`docker compose -f infra/docker-compose.yml exec -T postgres dropdb -U noctornal noctornal_scratch`
and repeat. The object-store tests still write test objects into the
buckets `MINIO_ENDPOINT` names, and no scratch database changes that.

Expect **no failures**. Both directories are needed: the suite spans two
pytest roots, and running one gives a number that matches nothing in the
documentation. The collected total for a given release is in
`release/CHANGELOG.md`.

**What skips depends on what this shell can reach (R7).** Each of these
is a correct result and not a broken install:

| Missing | What skips |
|---|---|
| `DATABASE_URL` | every database-backed test, roughly half the suite. The core of the suite is deliberately database-free so it can run anywhere. |
| `REDIS_URL`, `MINIO_ENDPOINT` or `SMTP_HOST` | the Redis, object-store and Mailpit legs |
| Node.js on `PATH` | the console's browser-side checks |
| `NOCTORNAL_APP_DB_ROLE` | `test_app_role_privileges_pg.py`, which checks what migration 0060 granted the least-privilege runtime role. That role exists only where Postgres was initialised with `NOCTORNAL_APP_DB_PASSWORD`, which the development stack does not set, so on an install made by these installers this file skips. |

CI provides all of these and fails the build on any skip.

The table is about settings, not services. The database, Redis and
object-store tests check only that their setting is present, not that
the service answers, so with `.env.local` loaded and the containers down
they **fail or error** rather than skip. Start the stack before running the
suite; `docker compose -f infra/docker-compose.yml ps` shows whether it
is up.

If `gpg` is not on your `PATH` you will additionally see PGP failures
rather than skips: `test_pgp.py` asserts the binary is present
deliberately, so a missing verifier is loud rather than silent. GnuPG is
optional for *operating* the product, which is true; it is not optional
for running the full suite green.
