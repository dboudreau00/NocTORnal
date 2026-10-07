# Installing NocTORnal

> **Read the [five blocking items](../README.md#five-blocking-items-none-of-them-a-software-problem)
> in the README first.** Five legal decisions, L1 to L5, gate any use of
> this software against real material. Installing it is fine; pointing it
> at a real case is not, until those are settled.
>
> **Legal review is required before any active case load**, and holding this
> material is dangerous in its own right: possession can be an offence, and
> a store of victim data and open investigations is a target. Until counsel
> has worked through `docs/18-legal-review-pack.md`, load only synthetic data
> or published reporting with no personal data. See "Read this before you
> hold anything" at the top of `docs/16-legal-and-external.md`.

---

## The quick path

**[START-HERE.md](START-HERE.md) is the one page to follow first.** It says
what you need, gives the three install steps for each system, explains the
first sign-in, and lists the five commonest problems with their fixes. This
document is the detail behind it.

## The short version

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy Bypass -File .\release\install.ps1
```

**macOS / Linux:**

```bash
bash release/install.sh
```

Both prefixes are needed. The default Windows client ExecutionPolicy is
`Restricted`, and a file extracted from a downloaded zip additionally
carries Mark-of-the-Web, so a bare `.\install.ps1` is blocked either way. A
`.sh` out of a zip has no execute bit, so `./release/install.sh` fails with
"permission denied" before bash ever sees it.

That is the whole thing. It is a wizard of eight numbered steps ("Step 3
of 8"). Step 1 looks at your computer and prints what it found (system,
Python, Docker, the API's port) before anything is changed. Then it installs
the Python packages into a virtual environment of its own, starts the
services, creates the database, makes you an account (on both systems, and
before the API starts), offers a fictional demo case, starts the API and
prints a closing card with the console URL. When a terminal and a desktop
are present it offers to open the page in your browser; `--open` (`-Open`
on Windows) does so without asking.

Re-running it is safe. Every step checks before it acts and reports what
it found. If a step fails it says in one sentence what to do.

Two questions are asked of a person at the keyboard and never otherwise.
When standard input is not a terminal (a pipe, cron, CI, a test harness) the
only input it reads is the email and then the display name for the account,
and the demo case loads only if you ask for it:

| Flag | Windows | Effect |
|---|---|---|
| `--demo` | `-Demo` | load the fictional demo case without asking |
| `--no-demo` | `-NoDemo` | do not load it and do not ask |
| `--open` | `-Open` | open the console in your browser once it is up |

The demo case is the synthetic network `bootstrap.py demo-network` makes,
marked TLP:CLEAR. All of it is fictional.

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
| **Disk** | 2 GB free | 1.5 GB was added by the Beta 1 install alone: 1.1 GB of images, a 273 MB `.venv`, and the data. Installing Docker Engine and the venv package on a bare Ubuntu took about 0.8 GB before that. |
| **OS** | Windows 10/11, macOS 12+, Linux | PowerShell 5.1 is supported and specifically tested for. |

Optional, and only for the features that use them:

| | For |
|---|---|
| **GnuPG** on `PATH` | Verifying PGP-signed vendor messages (Comms). Without it, verification returns "no verifier" rather than silently claiming a signature is good. |
| **Node.js** on `PATH` | The test suite's browser-side checks of the console. Without it they skip; the static checks still run. |
| **Google Chrome** | `scripts/screenshot_ui.py`, a development tool |

**Optional extras.** Two Python extras are installed only when asked
for: `telegram` (Telethon, for collecting from Telegram) and `yara`
(yara-x, for YARA scanning of samples). Ask for them with
`bash release/install.sh --with-telegram --with-yara` or
`.\release\install.ps1 -WithTelegram -WithYara`, and for the image with
the build argument `--build-arg NOCTORNAL_EXTRAS=telegram,yara`. A switch
that is given and fails stops the install, where the dev tools above
fail quietly. Without `telegram` the Telegram collection features refuse
and say how to install it; without `yara` samples are not YARA-scanned,
and the readiness register says so. yara-x publishes wheels for macOS 14
and newer only, so on macOS 13 leave `--with-yara` off.

---

## What the installer actually does

Nothing hidden, in this order:

1. **Checks your computer, and changes nothing.** Prints the system,
   Python and Docker versions and whether the API's port is free. Stops with
   a specific instruction if Python or Docker is missing or too old, if
   Python cannot build a virtual environment, if the Docker engine is not
   reachable, or if the port is taken.
2. **Creates a virtual environment** at `.venv` and installs the API and
   the ontology package into it.
3. **Generates secrets** into `.env.local`: a TOTP key-encryption key, a
   persona key and an ingest pepper, each made from 32 random bytes. *It
   never writes a default secret.* Beside them it writes the development
   stack's settings, and names each service by `127.0.0.1` rather than
   `localhost` (`DATABASE_URL`, `REDIS_URL`, `MINIO_ENDPOINT`, `SMTP_HOST`).
   If the file already exists it is left alone, except that a file with no
   persona key gains one, appended.
4. **Starts the containers** and waits for Postgres to report healthy.
5. **Applies the database migrations** (`alembic upgrade head`).
6. **Creates your account** if no user exists, and prints the password
   once with the enrolment QR for your authenticator. When a terminal is
   attached it then waits until you press Enter, so you have saved the
   password before anything else is printed.

   > **Windows note (R8, fixed).** `install.ps1` makes the account before
   > it starts the API, as `install.sh` does, and waits for you, so the
   > server log cannot scroll the password and the QR code off the screen.
   > If you installed with an older copy and have no credentials, run:
   >
   > ```powershell
   > .venv\Scripts\python scripts\bootstrap.py create-user --email you@example.org --name "Your Name"
   > ```
   >
   > It works in a fresh terminal with no exports: `bootstrap.py` reads
   > `.env.local` itself.

7. **Offers the demo case**, a fictional one, so there is something to
   explore (see the flags above).
8. **Starts the API** on 127.0.0.1 and prints the closing card: the console
   URL, the email to sign in with, how to start it again, how to stop it and
   where the help is. The port is checked in step 1, so if it is already
   taken the installer stops there and says so, before it builds anything
   (see Troubleshooting).

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
`ssh -L 9001:127.0.0.1:9001 you@the-host`. The console is the same on a
machine you installed over SSH: `ssh -L 8000:127.0.0.1:8000 you@the-host`,
then open <http://127.0.0.1:8000/ui/> on your own computer.

A stack created by an earlier release still publishes its ports on every
interface until its containers are recreated from this file.
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

# start everything again (the start scripts run scripts/launch.sh and
# scripts/launch.ps1 and nothing else):
bash release/start.sh         # or: powershell -ExecutionPolicy Bypass -File .\release\start.ps1
```

Re-running the installer starts everything too, and is how you pick up a new
release. `start.cmd` in the project folder does the same on Windows when you
double-click it.

Data lives in Docker volumes and survives `down`. To destroy it
completely, add `-v`, which deletes every case, exhibit and audit row,
irreversibly.

---

## Configuration

Settings come from the environment or `.env.local`. **Nothing has a
default secret**; a missing value produces a deliberate, explained refusal
rather than an insecure fallback.

`.env.local` names settings and nothing else. The installer, both launchers and
`scripts/_env.py` leave out a name that changes how programs start (`PATH`,
`HOME`, anything beginning `PYTHON`, `LD_`, `DYLD_`, `BASH_`, `DOCKER_`,
`COMPOSE_`, `GIT_`, `PIP_` or `NODE_`, `PSModulePath`, and a few shell
variables such as `IFS` and `ENV`), say so by name, and never print its value.
If you really need one, set it in your own shell.

The ones worth knowing:

| Variable | Effect if unset |
|---|---|
| `NOCTORNAL_TOTP_KEK` | A production start refuses. In development the API starts and sign-in is refused with a named 503, because no TOTP secret can be sealed or opened. Generated for you at install. |
| `NOCTORNAL_PERSONA_KEK` | A collection persona's credential can be neither sealed nor opened, so a persona cannot be enrolled or used and every act or poll that needs one is refused by name. A key of its own, never the TOTP key. Generated for you at install. In production only the collector service holds it (`infra/production/collector.env`). |
| `NOCTORNAL_COLLECTOR_INLINE` | Persona acts are queued for the collector process and wait for it. A development install sets it to `1`, so the API runs them itself; it is refused in production. Written for you at install. |
| `NOCTORNAL_INGEST_PEPPER` | Ingest keys cannot be issued. Generated for you. |
| `NOCTORNAL_PROHIBITED_CONTENT_POLICY`<br>`NOCTORNAL_DESIGNATED_PERSON` | **Sample ingest returns 451.** This is L1, and the refusal is the point. Set both only once counsel has written the policy. |
| `NOCTORNAL_SAMPLE_ORIGIN` | Sample downloads are refused. Invariant 10 requires malware bytes to come from a **separate origin**; an origin split that is only written down does not survive the first hurried deploy. |
| `NOCTORNAL_NOTIFY_ADDRESS_DOMAINS` | Analysts cannot redirect their own notification email at all. Fail-closed on purpose: a subject line carries a case code, and a case code is intelligence. |
| `NOCTORNAL_LIVE` | Live updates are on. Set to `0` behind PgBouncer in transaction mode, where `LISTEN` cannot work. |
| `NOCTORNAL_LIVE_MAX_SOCKETS` | 200 authenticated live subscribers per API process; the next is refused with close code 1013. |
| `NOCTORNAL_LIVE_MAX_PENDING` | A quarter of the subscriber ceiling (50 by default) of sockets that are open but not yet authenticated, per process. A peer with no session pays for these, so the budget is small, and a full budget is refused before the WebSocket handshake completes so that a refused socket holds nothing. |
| `NOCTORNAL_LIVE_MAX_PENDING_PER_PEER` | 8 of those per peer address, the same address the rate limiter uses, trusted proxy hops included. |
| `NOCTORNAL_LIVE_HELLO_SECONDS` | 10 seconds for an accepted socket to send its hello before it is closed and its slot returned. |
| `NOCTORNAL_RELAX_SEASONING_DAYS` | 7 days: the second person who approves turning off a case's merge requirement must have held `case.update` on that case for at least this long, read from the assignment's grant time by the database clock. `0` turns the rule off and is the only value that does; a value that is not a whole number from 0 to 365 is held to 7 and refused at a production boot. |
| `NOCTORNAL_ACT_WAIT_SECONDS` | 8 seconds: how long a route waits for the collector to finish a persona act it queued, before it answers "queued". Never more than 25. |
| `NOCTORNAL_ACT_TTL_SECONDS` | 900 seconds (15 minutes): how long a queued persona act may wait to be claimed before it lapses. Held between 60 and 3600. |
| `NOCTORNAL_DB_CONNECT_TIMEOUT` | 10 seconds to make a database connection before giving up. A value below 1 is held to 1, and one that is not a whole number reads as 10. |
| `NOCTORNAL_EGRESS_DB_WORKERS` | 8 threads for the egress proxy's reads of the database, from 1 to 64. Read by the proxy alone. |
| `NOCTORNAL_ANALYSIS_SOCKET`, `NOCTORNAL_ANALYSIS_LOCAL`, `NOCTORNAL_ANALYSIS_WORKER_CONCURRENCY`, `NOCTORNAL_ANALYSIS_WORKER_MAX_BYTES` | The isolated analysis worker (`infra/production/README.md`, Analysis worker, has the table). With no socket a production process refuses to parse hostile bytes; `NOCTORNAL_ANALYSIS_LOCAL=1` parses in a local child on purpose, and the register says so. The worker runs 2 requests at once (1 to 16) and reads at most 1 GiB. |
| `NOCTORNAL_ARCHIVE_MAX_MEMBERS`, `NOCTORNAL_ARCHIVE_MAX_TOTAL_BYTES`, `NOCTORNAL_ARCHIVE_MAX_MEMBER_BYTES`, `NOCTORNAL_ARCHIVE_MAX_RATIO`, `NOCTORNAL_ARCHIVE_MAX_DEPTH`, `NOCTORNAL_ARCHIVE_WALL_S`, `NOCTORNAL_ARCHIVE_MAX_TREE_MEMBERS` | Archive expansion limits. Unset: 200 members (1 to 10,000), 256 MiB of members in all, 64 MiB for one member, a ratio of 100 (2 to 10,000), 2 levels (1 to 5), 60 seconds (10 to 600), and 1,000 members across a whole tree (never below the per-archive count). A value that does not parse, or a byte cap the analysis memory cannot hold, is a named refusal at a production start. |
| `NOCTORNAL_SAMPLE_ANALYSIS_MEMORY`, `NOCTORNAL_SAMPLE_ANALYSIS_MAX_BYTES`, `NOCTORNAL_SAMPLE_FUZZY_MAX_BYTES`, `NOCTORNAL_SAMPLE_ANALYSIS_TIMEOUT_S`, `NOCTORNAL_SAMPLE_ANALYSIS_CONCURRENCY` | The bounds of a static-triage child. Unset: 2 GiB of address space (256 MiB to 64 GiB); the largest sample analysed is the sample upload cap or a third of what the memory leaves after the parser (about 512 MiB), whichever is less; the largest sample fuzzy-hashed is 32 MiB, or the analysis maximum if less; 300 seconds of wall clock for a step (10 to 3600); 1 run at once (1 to 8). A setting that does not parse, or a maximum the memory cannot hold, is a named refusal at a production start. |
| `NOCTORNAL_YARA_SCAN_TIMEOUT_S`, `NOCTORNAL_YARA_MAX_UPLOAD_BYTES` | A YARA scan of one sample stops after 60 seconds (5 to 600), and a rule set upload may be 32 MiB (1 MiB to 256 MiB). |
| `NOCTORNAL_EMBED_WORDING` | `on`: similar wording runs in this process, reads no model file and sends nothing. `off` turns it off; any other value is reported as a problem and leaves it on. |
| `NOCTORNAL_EMBED_MEANING_URL` and the other `NOCTORNAL_EMBED_MEANING_*` settings | Unset, similar meaning is off and nothing is sent. Set, it names the base address of a model server that speaks the OpenAI embeddings protocol (http or https, no user name or password, no query), reached only through the `embeddings` egress route, and needs `_MODEL` and `_CEILING` (the highest TLP it may receive, which has no default). Optional: `_KEY` (kept out of every log), `_AUTHORITY` (the recorded authority to send case text) and `_MESSAGE_AUTHORITY` (the same for message text), `_LOCAL_HOST` (declares that the host in the URL is this host, development on a direct route only), `_NETWORK` (the private network of IPv4 /16 or narrower, or IPv6 /64, that a named endpoint may resolve into), `_CA_FILE`, `_REVISION`, `_QUERY_PREFIX`, `_DOCUMENT_PREFIX`, `_DIMENSIONS`, `_MAX_CHARS` (2000, 200 to 32000), `_BATCH` (16, 1 to 128) and `_TIMEOUT_S` (30, 1 to 300). A setting with a placeholder, or one that does not parse, is a named problem and leaves meaning off. |
| `REDIS_URL` | Rate limiting falls back to per-process, and says so loudly at startup. In production it must sign in as `noctornal_limiter`, and the `redis` service refuses to start otherwise. |
| `NOCTORNAL_ENABLE_DOCS` | The OpenAPI schema stays off. It publishes the full route inventory of a law-enforcement case system, so it is opt-in. |

---

## A production deployment

Everything above installs a development stack on this machine. A
deployment other people use is `infra/production/` (one host, Docker
Compose, TLS, an egress proxy), and `infra/production/README.md` is its
procedure. The installers do one job there, on the host's own `python3`
(3.8 or later, no virtual environment), and start nothing:

```bash
sudo ./release/install.sh --production-secrets
```

```powershell
powershell -ExecutionPolicy Bypass -File .\release\install.ps1 -ProductionSecrets
```

With `sudo` on Linux, because those files are root's, mode 600, and run as
anybody else it can read none of them; on Windows, run it as the user who
owns them. A file it may not read is one sentence naming the file.

It writes and checks the secrets files beside the compose file. The schema
owner's credential goes in `postgres-init.env` and `migrate.env`, each
read by one service, and never in `secrets.env`, which every application
service reads (`docs/17` F52). The rate limiter's Redis gets a password and a
`REDIS_URL` that signs in as the limiter's own user, the only one that
Redis has. It prints the name of each change and never a value, and keeps
a backup of every file before it changes it.

Run it after every `git pull`, before `up`. Coming from Alpha 7a or an
earlier release it is required: it moves the owner's credential out of an
existing `secrets.env`, and until it has, the migrate job and Redis each
refuse to start with a sentence naming it, and nothing that waits on them
starts. [secrets-upgrade/README.md](secrets-upgrade/README.md) is that
upgrade step by step, with the way back.

**Backups and restore** are in `infra/production/README.md`, Day-to-day.
Read its Restoring paragraphs before you rely on a backup: a restore needs
the three runtime roles to exist before `pg_restore` runs, and a mirror of
the evidence bucket keeps the bytes of an exhibit lodged since Alembic 0139
but not the object version it records, so a restored exhibit reads as
missing until an owner step is run.

---

## Troubleshooting

**"port 8000 is already in use"**: an earlier copy of the API is still
running, or something else holds the port. Both installers stop with this
in step 1, before they build anything. If it is an earlier copy, the stack
is already up at <http://127.0.0.1:8000/ui/>. Otherwise stop what holds the
port, or pass `--port 8001` (`-Port 8001` on Windows).

**"No 'script_location' key found in configuration"**: you ran `alembic`
from `db/`. It must run from the repository root, where `alembic.ini`
lives. This reads as a broken install and is not one.

**`alembic` stops with "DATABASE_URL is not set or is empty"** in a new
terminal: unlike `bootstrap.py`, Alembic reads the environment only, and
it does not guess a target. Load `.env.local` first
(`eval "$(.venv/bin/python scripts/_env.py export)"`, which reads the file as
data and runs nothing from it, or the PowerShell line under Verifying the
install).

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
seconds**: the `.env.local` names the services `localhost`, as an older
installer wrote it. With Windows' default address preferences `localhost`
resolves to `::1` first, nothing listens there because the services are
published on 127.0.0.1 only, and a refused connection on Windows takes
about two seconds before the client tries 127.0.0.1. Replace `localhost`
with `127.0.0.1` in `DATABASE_URL`, `REDIS_URL`, `MINIO_ENDPOINT` and
`SMTP_HOST` in `.env.local`, which is what a new one carries. On Linux the
old file works as it is: there `localhost` reached every service in a
millisecond or less.

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
eval "$(.venv/bin/python scripts/_env.py export)"
docker compose -f infra/docker-compose.yml exec -T postgres createdb -U noctornal noctornal_scratch
docker compose -f infra/docker-compose.yml exec -T postgres psql -U noctornal -d noctornal_scratch -q -f /docker-entrypoint-initdb.d/00-extensions.sql
export DATABASE_URL=postgresql+psycopg://noctornal:dev_only_change_me@127.0.0.1:5432/noctornal_scratch
.venv/bin/alembic upgrade head
.venv/bin/python -m pytest apps/api/tests packages/ontology -q
```

```powershell
# Windows
Get-Content .env.local | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*=' -and $_ -notmatch '^(PATH|PATHEXT|HOME|COMSPEC|IFS|ENV|CDPATH|GLOBIGNORE|SHELLOPTS|BASHOPTS|PROMPT_COMMAND|PS[1-4]|PSMODULEPATH)=|^(BASH_|LD_|DYLD_|PYTHON|DOCKER_|COMPOSE_|GIT_|PIP_|NODE_)' } | ForEach-Object { $k, $v = $_ -split '=', 2; Set-Item "env:$k" $v }
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

**What skips depends on what this shell can reach.** Each of these
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
