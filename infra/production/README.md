# Production deployment: one host, docker compose

This directory is the whole deployment: a reverse proxy, Postgres, Redis,
MinIO, the API, a second process serving the sample origin, a cron
loop, and the collector, the one process that holds the persona key. There is no Kubernetes here and no cloud service; the target is one
Linux box you control.

Read [What you are NOT getting](#what-you-are-not-getting) before you rely
on this for casework. It is short and it is the honest part.

---

## Before you start

You need:

* A Linux host with Docker Engine and the Compose v2 plugin (2.24 or later,
  for the optional egress env files), and root on it.
* **Two** DNS names pointing at that host: one for the console, one for
  sample downloads. They must be genuinely separate names. Invariant 10
  puts hostile bytes on an origin that holds no analyst session, and the
  runtime cannot tell a real split from a CNAME onto the same host
  (`docs/16` C9), so nothing will catch it for you if they are not.
* Ports 80 and 443 reachable from wherever your analysts are. Nothing else
  is published: Postgres, Redis, MinIO and both application processes are
  reachable only from the compose network.
* A checkout of this repository on the host. Every command below is run
  from the repository root. Nothing but the repository belongs in it: that
  directory is the build context of the one image every service runs, so a
  stray file there is copied into every container by the next
  `up -d --build`. In particular a database dump never goes there (see
  Backups).
* `python3`, 3.8 or later, for the installer step that writes the secrets
  files (it uses the standard library alone).

Counsel has work to do before an analyst signs in. See
[What stays red, and what a red check refuses](#what-stays-red-and-what-a-red-check-refuses).
Doing it after the stack is up is fine; doing it after the first ingest is
not, and the collection route refuses to poll until it is done.

---

## 1. Write the secrets files

```sh
( umask 077
  cp infra/production/secrets.env.example infra/production/secrets.env
  cp infra/production/caddy.env.example   infra/production/caddy.env )
sudo ./release/install.sh --production-secrets
```

The parentheses are deliberate. The `umask` is there so the two files are
created private from the first byte, and it must end with the subshell: left
in force in your shell it would also make everything you create afterwards
unreadable to the containers (the TLS directory and certificate in step 3,
and every file a later `git pull` writes, because the image keeps the modes it
copies). Whatever your shell's own `umask` is, [check the modes
before you start the stack](#4-start-it).

The second command (`release\install.ps1 -ProductionSecrets` on Windows,
as the user who owns the files) needs only a `python3` on the host. It
runs with `sudo` because the files it writes are root's and mode 600,
which the lock-down below makes all of them, and run as anybody else it
cannot read them; edit them afterwards with `sudoedit`. It creates
`postgres-init.env` and `migrate.env` beside `secrets.env` from their
templates, mode 600, and writes the secrets that are machine-chosen and
must agree across files:

* the **Redis password** and `REDIS_URL`, which signs in as the limiter's
  own Redis user (see [The limiter's Redis](#the-limiters-redis));
* the **schema owner's password**, into `postgres-init.env` and inside
  `migrate.env`'s DSN, but only when Docker says the database volume does
  not exist yet. initdb fixes the owner's password for good, so on a host
  where it cannot tell, the command asks you to choose it instead.

It prints the name of everything it changed and never a value, and exits
non-zero while something is left for you, saying what. Run it again after
you have done that; it changes only what still needs changing.

Four files so far, because four different readers must hold four different
things (the two egress files are in [Egress](#egress-the-only-way-out)):

| File | Read by | Holds |
|---|---|---|
| `secrets.env` | every service but Caddy, the migrate job and the egress proxy | everything below that a running process needs |
| `caddy.env` | Caddy alone | the two hostnames and the TLS mode |
| `postgres-init.env` | postgres alone | the passwords initdb takes: the owner's `POSTGRES_PASSWORD`, the system role's, the egress role's |
| `migrate.env` | the migrate job alone | `NOCTORNAL_MIGRATION_DATABASE_URL`, the owner's DSN |

The owner `noctornal` is the Postgres image's bootstrap superuser. Row-level
security does not bind it, and it can switch off the append-only triggers
on the audit and custody tables in one statement, so its credential is in
no file a running service reads (`docs/17` F52). `compose.yml` hands every
service but postgres and the migrate job both variables empty, whatever
`secrets.env` says; the API and the cron jobs refuse to run holding either
(and refuse a published credential too, with one code, 2, so an alert can
tell a job that would not start from a pass that failed); and the migrate
job refuses to run without its DSN, or with one still carrying a
placeholder. Moving an existing deployment to this layout is
[release/secrets-upgrade/README.md](../../release/secrets-upgrade/README.md).

`secrets.env.example` is the reference for every variable: what it is, and
what breaks when it is wrong. Work through it top to bottom. The API
refuses to start on a placeholder it can recognise, and several other
values fail quietly rather than loudly.

`caddy.env` holds the three values the TLS terminator needs (the two
hostnames and the TLS mode) and nothing else. Caddy is the one process the
internet reaches before any sign-in, so it does not receive `secrets.env`.
On a tree from before 2026-10-03 those three lines lived in `secrets.env`:
copy them into `caddy.env` before `up`. Without the file compose refuses
the whole stack up front, before it stops anything that is running.

Generate passwords from a URL-safe alphabet, because four of them are
embedded in URLs and an unencoded `@`, `:`, `/` or `#` silently truncates a
DSN into a different, valid-looking one:

```sh
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

**The TOTP key-encrypting key** is the one value with a shape requirement.
It must be base64 that decodes to **exactly 32 bytes**. This is the method
`release/install.sh` uses, and it checks the length for a reason. In this
deployment the boot check catches a bad one for you: `NOCTORNAL_ENV` is
`production`, so the API runs the envelope's own reader before it serves
anything and refuses to start, by name. Everywhere else the first thing to
notice is a second factor that cannot be sealed or opened, a different
program, long after anyone would connect the two.

```sh
python3 -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

Losing that key costs far more than the second factors. It seals every
column `apps/api/src/noctornal_api/security/sealed.py` lists: each
account's TOTP secret, each stored victim credential, the data key of every
sample (preserved samples included) and each configured integration's
credential. A collection persona's credential is sealed by a key of its
own, `NOCTORNAL_PERSONA_KEK`, in `collector.env` (see
[The collector](#the-collector-the-one-service-that-holds-the-persona-key)).
A database restored without the key that sealed it opens none of them: no
enrolled account can complete a sign-in (it answers 503), and no victim
credential or sample can be read again.
Nothing recovers them short of the key, so back it up with every backup of
the database, somewhere that is not this host. Rotating it loses nothing:
the envelope keeps a ring (`NOCTORNAL_TOTP_KEK_RETIRED`, see the
template), the readiness check `kek_ring_opens_stored_secrets` says
whether every stored secret still opens, and
`scripts/rewrap_secrets.py --apply` moves them under the new key.

Then lock the files down. Between them they hold every password in the
deployment, and the egress files below hold the proxy's keys and database
password. The subshell's `umask` above created `secrets.env` and `caddy.env`
private, and the installer step creates the files it writes mode 600, owned
by whoever ran it, which with `sudo` is root already; this makes all of them
root's:

```sh
sudo chown root:root infra/production/secrets.env infra/production/caddy.env infra/production/postgres-init.env infra/production/migrate.env
sudo chmod 600      infra/production/secrets.env infra/production/caddy.env infra/production/postgres-init.env infra/production/migrate.env
```

Every `.env` file in this directory is excluded from the image build
(`.dockerignore`) and from git (`.gitignore`), and a test holds both lists to
each other, so a file you add here is not baked into an image. They are still
plain files on this host.

Do not put a colon in `MINIO_ROOT_USER` or `MINIO_ROOT_PASSWORD`. The
`minio-init` service hands them to `mc` as a URL, where a colon ends the
access key, and it refuses a pair with one by name. A password from
`token_urlsafe` never has one.

> `docker compose config` prints these files' contents, resolved into each
> service's environment. Do not paste that output into a ticket.

Write one more file before the first `up`: `collector.env`, which holds the
persona key and is read by the collector service alone (see
[The collector](#the-collector-the-one-service-that-holds-the-persona-key)).
Without it the collector refuses to start and **nothing is polled**, feeds
no persona reads included.

---

## 2. Check the two passwords that are written twice

`POSTGRES_PASSWORD` (`postgres-init.env`) also appears inside
`NOCTORNAL_MIGRATION_DATABASE_URL` (`migrate.env`), and
`NOCTORNAL_APP_DB_PASSWORD` also appears inside `DATABASE_URL`. The
installer step compares the first pair and says so when they differ;
nothing compares the second. A mismatch surfaces on first boot as the
migration job failing to authenticate, which reads like a bug in the
migration.

There are two Postgres roles on purpose. `noctornal` owns the schema and is
the only thing that ever runs Alembic. `noctornal_app` is least privilege,
is not the owner, and cannot `ALTER TABLE ... DISABLE TRIGGER`, which is
precisely what a compromised API process would want in order to write
around the audit and custody chains. The app role is created by
`db/init/10-app-role.sh` **at initdb**, and initdb scripts run once against
an empty data directory: changing `NOCTORNAL_APP_DB_PASSWORD` later does
nothing to an existing cluster, and you have to `ALTER ROLE` by hand.

**A volume that was initialised without that password has no `noctornal_app`
at all.** There is then nothing for `DATABASE_URL` to name, and production
refuses to start on the owner or a superuser (the refusal names the
variable, never the role). Either start from a fresh volume with the password
set (`down -v` destroys the case file and the evidence, so only where there is
nothing in it), or repair the running cluster with the repository's own
script, which creates `noctornal_app` and `noctornal_worker` with no password
and grants them what the migrations grant:

```sh
docker compose -p noctornal-prod -f infra/production/compose.yml run --rm --no-deps migrate \
  sh -c 'DATABASE_URL="$NOCTORNAL_MIGRATION_DATABASE_URL" python scripts/runtime_roles.py ensure --production'
docker compose -p noctornal-prod -f infra/production/compose.yml exec postgres psql -U noctornal -d noctornal
#   at the psql prompt:   \password noctornal_app     and      \password noctornal_worker
```

`\password` asks for the new password at a prompt and hashes it in `psql`, so it
is on no command line and in no log. Put the same passwords in `DATABASE_URL`
and `NOCTORNAL_WORKER_DATABASE_URL`, then `up -d`.

---

## 3. Give MinIO a certificate

The API refuses to start unless `MINIO_SECURE` and `SAMPLE_SECURE` are both
`true` (`apps/api/src/noctornal_api/config.py`). The argument is not about
the password (under SigV4 the secret key never crosses the wire) it is
that every exhibit's bytes do, and each request carries a signature
anything on the path can lift and replay against the evidence bucket until
it expires.

MinIO looks for `public.crt` and `private.key` in its certificate
directory, so those are exactly the names:

```sh
mkdir -p infra/production/tls
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout infra/production/tls/private.key \
  -out    infra/production/tls/public.crt \
  -subj   "/CN=minio" \
  -addext "subjectAltName=DNS:minio"
chmod 755 infra/production/tls
chmod 644 infra/production/tls/public.crt
sudo chown root:root infra/production/tls/private.key
sudo chmod 600       infra/production/tls/private.key
```

The two `chmod` lines state the modes instead of trusting your `umask`, and
they are not decoration. Every container drops all Linux capabilities, so
root inside one is an ordinary user to the files it is given: it reads only
what it owns or what `other` may read. The application containers (uid
10001) read `public.crt`, and MinIO and `minio-init` (root, without
`DAC_OVERRIDE`) read it too without owning it. Only `private.key` is private,
and it is root's, which is the one file MinIO opens as its owner. A directory
or certificate left `0700` or `0600` by a `umask` of `077` breaks the stack
without saying why: every loop service and the API stop at the
`cat ... /certs/public.crt` step of their start-up, and MinIO, which cannot
read its certificate, starts on plain HTTP and the stack never reaches
"buckets ready".

`DNS:minio` is load-bearing. `minio` is the compose service name, it is
what `MINIO_ENDPOINT` and `SAMPLE_ENDPOINT` address, and it is the name
each client checks the handshake against. A certificate for anything else
produces a hostname-mismatch error on the first exhibit.

The certificate is self-signed and no public CA vouches for it, so the
application containers are told to trust it: each one concatenates the
system CA bundle with `public.crt` at start and points `SSL_CERT_FILE` at
the result.

It is a concatenation rather than the certificate alone because the clients
in this build do not read that variable the same way. The MinIO client
hands it to urllib3 as `ca_certs`, which makes that file the *entire* set of
roots the evidence, raw and sample clients will trust. Everything else,
RSS collection, the webhook channel, SMTP, the readiness probe, goes
through OpenSSL's default verify paths, which are `SSL_CERT_FILE` **and**
`SSL_CERT_DIR`; the directory still points at `/etc/ssl/certs` and the image
ships the hashed symlinks, so those clients keep the public roots either
way. Pointing the variable straight at `public.crt` would therefore not
break them, whatever the certificate count suggests. The concatenation is
kept because it costs one `cat` and removes the dependency on a base image
that ships those symlinks.

`infra/production/tls/` is gitignored.

---

## 4. Start it

First check the modes of the files the containers read from this checkout.
A clone or a `git pull` made under a restrictive `umask` (some hardened hosts
default to `077`) leaves them `0600`, and the containers cannot read what they
do not own: Caddy reads `Caddyfile`, `minio-init` reads `mc-alias.sh`, MinIO and
the application read the `tls` directory and `public.crt`, and Postgres reads
`db/init`. This prints nothing when they are right (`private.key` is skipped
on purpose, it is root's and private):

```sh
find infra/production/Caddyfile infra/production/mc-alias.sh infra/production/tls db/init \
  ! -name private.key \( -type f ! -perm -o=r -o -type d ! -perm -o=rx \) -print
```

Whatever it names, open up with `chmod go+rX <path>` (a directory needs `x` as
well as `r`), and run it again after every `git pull`. The image itself does
not depend on this: the Dockerfile makes everything it copies readable, so a
checkout made under `077` cannot produce an image the application cannot read.

```sh
docker compose -p noctornal-prod -f infra/production/compose.yml up -d --build
```

`--build` matters. Compose reuses an existing local image tag, so after any
code change an `up -d` without it redeploys the old image and you see no
change.

The order is enforced by the file, not by you: Postgres reaches a real TCP
healthcheck, the migration job runs `alembic upgrade head` as the owner and
must succeed, MinIO's buckets are created, and only then do the API, the
sample origin and the cron loop start. A migration that will not apply
means an API that never starts, which is the correct outcome, code ahead
of its schema fails on the first query touching a new column and reports
that as a bug in whatever endpoint happened to run first.

Watch it come up:

```sh
docker compose -p noctornal-prod -f infra/production/compose.yml ps
docker compose -p noctornal-prod -f infra/production/compose.yml logs -f migrate api
```

`migrate` and `minio-init` are one-shot and are expected to sit in `exited
(0)`. Everything else should be `running`, and `api`, `sample-origin` and
`analysis-worker` should reach `healthy`.

### If the API refuses to start

It will print every reason at once, each naming a variable and what it
costs. That list is the whole fix. There is no second problem waiting
behind the first. It never quotes a value, so the output is safe to read
over someone's shoulder.

### If `up` fails creating the network

`Pool overlaps with other one on this address space` means another Docker
network on this host already holds `172.31.243.0/24` (or one of the egress
networks, `172.31.244.0/24` to `172.31.246.0/24`). Pick a free /24 and
change it in **two** places in `compose.yml`: the `networks:` block at the
bottom and the `x-caddy-ip` alias at the top. They must agree. The second
is the address uvicorn is told to trust for `X-Forwarded-For`.

---

## 5. Create the first account

While `iam.app_user` is empty (and only then) one route creates the first
administrator. It hands out `SYS_ADMIN`, `SECURITY_OFFICER`, `CASE_OWNER`
and `ANALYST`, which is right for a single-operator install and clears the
two account-shaped readiness items in one call, `security_officer_present`,
which is blocking, and `sys_admin_present`, which is not. It answers 409
forever afterwards, and it counts every row, active or not.

**It needs a secret only you hold.** Caddy publishes 80 and 443 as soon as
the API is up, the hostname is in certificate-transparency logs within
seconds of the certificate being issued, and the route's path is public in
this repository, so whoever called it first on an open address would own
the deployment's administration and the officer role that reviews
break-glass. Two ways to do step 5, and the first is the default:

- **From the server, no web door at all.** Leave `NOCTORNAL_SETUP_TOKEN`
  unset in `secrets.env` (it ships commented out). In production the route
  then does not exist (404, as an unknown path answers) and the console never
  offers the first-run card. Create the account with the command in the
  second block below.
- **Through the web, with a one-time setup token.** Before `up`, put a
  token of at least 32 characters in `secrets.env`, for example the output
  of `openssl rand -hex 32`, as `NOCTORNAL_SETUP_TOKEN=...`. The API
  refuses to start with a shorter one. The route then answers only a request
  that carries it in an `X-Setup-Token` header, or typed into the console's
  first-run card, which asks for it when the server says it is needed. A
  missing or wrong token is a 403, compared in constant time and counted
  against the sign-in failure limit.

`$NOCTORNAL_SETUP_TOKEN` below is a variable in your own shell, not a file
the command reads, so set it first to the value you put in `secrets.env`
(`export NOCTORNAL_SETUP_TOKEN=...`) and `unset NOCTORNAL_SETUP_TOKEN` when
you are done. An unset one sends no usable token, and the route answers 403.

```sh
curl -sS -X POST https://YOUR-CONSOLE-HOSTNAME/api/v1/setup/first-admin \
  -H 'content-type: application/json' \
  -H "x-setup-token: $NOCTORNAL_SETUP_TOKEN" \
  -d '{"email":"you@example.org","display_name":"Your Name"}'
```

Add `-k` while `NOCTORNAL_TLS_MODE=internal`: those certificates come from
Caddy's own CA and nothing public trusts them.

The token is one-time in the way that matters: it opens the door only while
the table is empty, and once the first account exists the route answers 409
whatever is sent. Then delete the line from `secrets.env` and run `up -d`
again, so the secret does not stay in the environment of every service.

**The credentials come back once and are not retrievable.** Save them, then
sign in at `https://YOUR-CONSOLE-HOSTNAME/ui` and enrol your authenticator.

To make the first account from the server instead (and this is the only way
when no token is set), run it from a container:

```sh
docker compose -p noctornal-prod -f infra/production/compose.yml \
  run --rm --no-deps api python scripts/bootstrap.py create-user \
  --email you@example.org --name "Your Name" \
  --roles SYS_ADMIN,SECURITY_OFFICER,CASE_OWNER,ANALYST
```

Note the explicit `--roles`: the script's own default is
`CASE_OWNER,SYS_ADMIN` and leaves you with no `SECURITY_OFFICER`, which
means break-glass refuses every request because nobody can review one.

---

## 6. The readiness register

```
GET /api/v1/admin/readiness
```

Forty-five checks, each with the evidence behind it and, when it fails, the
action that fixes it. It needs `user.manage`, which is a step-up
permission, so re-enter your second factor first.

`ready: true` means the code-side preconditions hold. It does **not** mean
the deployment is lawful, and `readiness.py` is explicit that it never did:
several entries in `docs/16` are decisions only a human can take, and the
software records declarations it cannot verify.

The sample origin runs its own copy of the register at the same path on its
own hostname, and that is the only way to confirm the split from the
outside: the process there should report `sample_origin_configured` as
"this process is the sample origin", while the console's reports "this
process is configured as the application origin and refuses every
download". Both are correct. That pair of answers is the origin split
working.

> The sample-origin process serves only the sample download, its preflight,
> `/healthz` and that readiness endpoint. Everything else 404s there, on
> purpose: the console, the login form and every case route must not exist
> at the hostname that serves hostile bytes.

### What stays red, and what a red check refuses

Four of the forty-five are **blocking** (`readiness.BLOCKING_CHECKS`):
`prohibited_content_policy`, `sample_origin_configured`,
`retention_rules_confirmed` and `security_officer_present`. "Blocking" is
not a synonym for important, everything in the register is important. It
means a caller refuses on it: `POST /api/v1/collection/sources/{id}/run`
answers 409 and names the failing checks while any of the four is open, so
a covert poll against a real target cannot run before somebody has settled
them.

`sample_origin_configured` is on that list and should be green by the time
you get here: step 1 sets `NOCTORNAL_SAMPLE_ORIGIN`, and this compose file
runs the second process that satisfies it. The other three are the ones a
correctly configured stack still comes up red on, because two of them are
decisions nobody but a human can take and the third needs an account that
does not exist yet.

`sys_admin_present` is also red on a fresh stack and is deliberately **not**
blocking, `readiness.py` says why at length: it is an operability failure
rather than a decision taken too late, and refusing on it would land on
somebody who cannot act on the refusal, because the register that explains
it needs `user.manage` and `SYS_ADMIN` is the only role that holds it.

Two more are green on a correctly written secrets file and worth knowing
by name. `evidence_size_cap_declared` is red until
`NOCTORNAL_MAX_EVIDENCE_BYTES` is declared (the boot refuses without it,
so in this deployment you cannot reach the register with it unset) and
goes red again if the variable is edited without a restart, because the
cap is read once at start. `kek_ring_opens_stored_secrets` opens stored
secrets with the key ring and is the check that catches a KEK that
changed under its id; it is green on a fresh stack and stays so through a
rotation done as the template describes.

Two report on what the boot check and `docs/16` C8 ask of the secrets file
and of Redis. `credentials_not_published` names every credential that still
carries a value this repository, its CI or MinIO publishes (a `replace-me`
placeholder, the development password, a key of one repeated byte, a Redis
URL with no password); in this deployment the API refuses to start on any
of them, so it is green whenever you can read it. `redis_limiter_isolated`
reads the limiter's Redis ACL over the limiter's own connection, and
counts keys in that Redis that are not under its `rl:` prefix, and keys in
that instance's other databases, without reading a value. In production it
fails when the ACL does not confine the limiter (see
[The limiter's Redis](#the-limiters-redis)); it is green on this compose
file's Redis, which nothing else uses.

**1. `prohibited_content_policy`**, `docs/16` L1. Sample ingest is refused
until `NOCTORNAL_PROHIBITED_CONTENT_POLICY` and
`NOCTORNAL_DESIGNATED_PERSON` are set, and setting them is a declaration,
not a control: a false one produces a working system and an unlawful
deployment. Counsel has to write the policy first, and it has to settle who
is notified when screening trips, what the `REJECTED` path does with the
bytes (this build **preserves** them by default: moved into the
object-locked `PRESERVE_BUCKET` under a legal hold, still encrypted, and
retrievable only by a lead investigator a Security Officer has authorised.
Set `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=destroy` only where the policy
requires destruction, and destruction is still refused under a legal
hold), the reporting obligations in both
operating jurisdictions, and whether you are authorised to hold known-
material hash sets at all. Then point the variable at something an auditor
can follow and restart the API.

**2. `retention_rules_confirmed`**, `docs/16` D3. Six retention rules ship
as placeholders. The periods are jurisdictional and this build cannot
choose them, so each one waits for a named human to attach a rationale:

```
GET  /api/v1/retention/rules            (lists which are still placeholders)
POST /api/v1/retention/rules/{category} {"retain_days": N, "rationale": "..."}
```

`retention.manage` is step-up gated. The point of the confirmation is not
the number. It is that somebody's id is attached to it, and that the
rationale answers "why does this category expire when it does" to somebody
who was not in the room.

**3. `security_officer_present`** (blocking) and **`sys_admin_present`**
(not), both are cleared by step 5, which is why that step grants both
roles. `audit.read` and break-glass review are held by `SECURITY_OFFICER`
alone, and `user.manage` by `SYS_ADMIN` alone: with neither, the only
repair path is a database shell.

`smtp_configured` will also be red until `SMTP_HOST` names a relay that
speaks TLS. That one is configuration rather than a decision, and
`SMTP_ALLOW_PLAINTEXT` must stay unset. It exists for a development
Mailpit, and a production deployment carrying it sends case summaries in
the clear on the day STARTTLS fails.

---

## The limiter's Redis

Redis holds the rate limiter's meters and nothing else, and since
2026-10-02 that is a property of the server rather than a hope. The
`redis` service builds an ACL file at every start from `REDIS_PASSWORD`
(stored as its SHA-256, never the password) in which:

* the **default user is off**: no password, no command, no key. A client
  that does not sign in is refused, not signed in as anybody;
* **`noctornal_limiter`** is the only user. It may read and write keys
  under `rl:` and no other, use no pub/sub channel, and run exactly the
  commands the limiter and its readiness rows send
  (`ratelimit_redis.LIMITER_ACL_COMMANDS` lists each with the reason it is
  there). It cannot `FLUSHALL`, `CONFIG SET`, `KEYS`, `DEL` or read or
  write a key outside `rl:`.

What that does not confine, so nobody reads more into it: three of those
commands reach past the limiter's own keys without reading or writing one.
`SCAN` lists every key **name** in its database (the readiness census
counts the ones outside `rl:`), `INFO` reports the server's statistics,
and `ACL GETUSER` reads any user's rules and password hashes, which here
means its own and the disabled default's, neither of which has a hash
anybody else could use.

`REDIS_URL` must sign in as that user with that password:
`redis://noctornal_limiter:PASSWORD@redis:6379/0`. While `REDIS_URL` names
this service (host `redis`), the `redis` service compares the two as text
and refuses to start when they disagree, because a URL with no user name
signs in as the disabled default user and every limit that fails closed,
the login among them, would then refuse everyone. The installer step
writes both. Changing the password costs a restart and nothing else: no
data is stored with it.

`redis_limiter_isolated` reads this ACL back over the limiter's own
connection (`ACL WHOAMI`, `ACL GETUSER`) and, under
`NOCTORNAL_ENV=production`, fails when the limiter signs in as `default`,
when the default user is enabled (open with no password, or behind one),
or when the limiter's user holds a key outside `rl:`, a channel, a
selector, a category or a command it does not send. What it cannot see,
it says: another user the ACL defines would show only in its key census.

### A Redis of your own instead

Point `REDIS_URL` at it, on any host but `redis`. Give it the same shape:
a user for the limiter with the rules above
(`ratelimit_redis.limiter_acl_rules()` returns them), `default` disabled,
`noeviction`, and that user named in `REDIS_URL`. `redis_limiter_isolated` holds it to that
in production, and `redis_limiter_store` to the eviction policy.

Nothing here checks that Redis for you before it is used: the installer
step leaves a `REDIS_URL` naming another host alone and says so, and the
bundled `redis` service, seeing it, starts with its own ACL and no client
and says that on its log. It still starts because api, cron, lab-cron and
the sample origin wait for it to be healthy, and an idle Redis costs one
container. To leave it out, add `--scale redis=0` to every `up`; services
that wait on a service scaled to nothing do not wait for it:

```sh
docker compose -p noctornal-prod -f infra/production/compose.yml up -d --build --scale redis=0
```

An `up` without the flag starts it again, idle, and nothing else changes.

---

## Egress: the only way out

In this deployment the `noctornal` network is internal. The API, the cron
loop and the sample origin have no route to the internet. Two services do:
Caddy, which publishes 80 and 443, and the **egress proxy**, which is how
everything else leaves. The API and cron reach it at
`NOCTORNAL_EGRESS_PROXY_URL` (`http://172.31.243.11:3128`). It speaks HTTP
CONNECT and SOCKS5 on that one address. No port of it is published. It
decides every connection by route, records each one in
`collect.egress_connection`, and refuses private address space unless an
administrator's route names it. There is one proxy and no failover. When it
is down nothing leaves, which is the safe direction.

There are two kinds of route:

* **persona routes**: an egress profile per persona (a residential pool, a
  VPN, a Tor sidecar), plus one **passive default** that feeds read through
  from this host's own address. A persona connection is let out only for a
  running collection, a live two-person collection authority, or a logout,
  and only to the site of the source it serves.
* **integration routes**: `smtp`, `webhook` and the others the build
  registers, each allowed exactly the host and port entries an
  administrator added. There is no wildcard.

Both are configured under **Administration, Egress** (or with
`python scripts/egress_setup.py`, which signs you in with your password and
a current authenticator code). A fresh install has no route, so nothing
leaves until you create them.

### Keys and files

The egress keys are **not** in `secrets.env`, which every application
service receives. They are in three files beside it:

| File | Read by | Holds |
|---|---|---|
| `egress-proxy.env` | the egress proxy alone | its database URL, the client key, the seal key, the fingerprint key |
| `egress-client.env` | api, cron and the collector | the client key, the fingerprint key, the seal key's public half |
| `postgres-init.env` | postgres alone | `NOCTORNAL_EGRESS_DB_PASSWORD`, for `db/init/20-egress-role.sh`, beside the owner's and the system role's passwords (step 1) |

```sh
python scripts/egress_setup.py keygen     # prints every key, once
( umask 077                               # a subshell: the umask must not outlive these two lines
  cp infra/production/egress-proxy.env.example infra/production/egress-proxy.env
  cp infra/production/egress-client.env.example infra/production/egress-client.env )
sudo chown root:root infra/production/egress-proxy.env infra/production/egress-client.env
sudo chmod 600       infra/production/egress-proxy.env infra/production/egress-client.env
# postgres-init.env exists since step 1 (root's, mode 600): set
# NOCTORNAL_EGRESS_DB_PASSWORD in it with sudoedit, and do not copy its
# template over it, which would put a placeholder where the owner's password is.
python scripts/egress_setup.py preflight  # checks all three before you start
```

Preflight also refuses a value still carrying a `replace-me` placeholder,
the database password lines included: the proxy's role password is public in
this repository until you change it, and agreeing in both files does not make
it private.

Nothing in this directory is copied into the image except the `.example`
templates and the compose file: the Dockerfile copies the whole checkout
into the one image every service runs, so `.dockerignore` leaves out all of
`infra/production/` and lets back in only those two kinds of tracked file,
whatever a file in it is called. A `collector.env.old` or a `secrets.env.bak`
(each holds what the file held) is covered as well as the files named above.
The same file keeps an `.env`, a key, a backup and an editor copy out
wherever they land in the tree, at every depth. `test_dockerignore_secrets.py`
fails when a path `.gitignore` keeps out of a commit reaches the image, so a
file you add here is covered without anyone editing either list.

The client key and the fingerprint key must be the same in both env files;
preflight says so when they are not. **Losing the seal key loses every
sealed exit**: each must be sealed again. Losing or changing the
fingerprint key stops every chained exit until each is sealed again, and
every reseal counts as a widening that voids the collection authorities
recorded before it. Back all three files up with `secrets.env`.

The three files are optional to compose so that an upgraded tree still
starts. That needs **Docker Compose 2.24 or later**; an older one refuses
the whole file. A process that is missing a key then refuses to start and
names it.

### What a human still has to confirm

The readiness row `egress_boundary` probes the proxy with this process's
own key and reads this process's routing table. It cannot see the host.
Confirm once, and after every Docker or firewall change, that an internal
network really has no route out:

```sh
docker network inspect noctornal-prod_noctornal --format '{{.Internal}}'   # true
docker compose -p noctornal-prod -f infra/production/compose.yml exec api \
  python -c "import socket; socket.create_connection(('1.1.1.1', 443), 5)"
# must FAIL (network unreachable or a timeout); this command connects to
# 1.1.1.1 and nothing else, and only when you run it.
```

Docker's embedded resolver answers the containers' DNS queries and forwards
the ones it cannot answer to the host's resolvers, so a name can still leave
the host as a lookup even though no connection can. The readiness row says
so as a standing caveat and sends no query itself.

### Sidecars and local model servers

A Tor or VPN sidecar goes on the `exits` network, and its address in
`NOCTORNAL_EGRESS_UPSTREAM_ALLOW` (inside `172.31.245.0/24` and nowhere
else). Only the proxy joins that network, and the proxy hands a sidecar that
is not Tor a checked address rather than a name, so a site answering with a
private address cannot reach this host through it. No integration entry
can name the `exits` network, so no integration can leave through a
persona's exit. A model server for embeddings goes on the separate `models`
network (internal, joined by the proxy and the model alone) and is named by
an `embeddings` route entry with that network, for example
`model@172.31.246.0/24:8080` where `model` is the service's name. A model on
the host itself is reached by adding
`extra_hosts: ["host.docker.internal:host-gateway"]` to `egress-proxy` and
an entry naming `host.docker.internal` with its network.

### Upgrading an existing deployment

`release/egress-upgrade/README.md` has the order: keys, the three files,
the role for an existing volume (`python scripts/egress_setup.py role-sql`),
preflight, `up`, then `python scripts/egress_setup.py adopt`, which proposes
the passive default and the smtp and webhook routes from your current
settings and creates them when you confirm. Until adopt has run, feeds and
deliveries are refused for want of a route, and the readiness row
`egress_routes_cover_sources` says so.

---

## Analysis worker

Static triage and forum parsing read bytes written by the people under
investigation. Each read runs in a bounded child process, and a child
started beside the application can, on Linux, read the environment of
every process of the same user (all of `secrets.env`) and reach the
database over the shared network (`docs/17` F42). So in this deployment
no such child runs in `api`, `cron`, `collector` or `lab-triage`. They hand each read
to the **analysis worker**, a container with no secrets and no network,
over a Unix socket, and it starts the same child with the same limits.

It is not a task worker: there is no queue, nothing is scheduled, and each
request is one connection and one child. What `compose.yml` gives it:

* no `env_file` and no variable but its own three settings (the table
  below) and what Docker and the base image set. The worker refuses to
  start holding any other variable, and readiness asks it what it holds;
* `network_mode: none`, so loopback only: no route, no DNS, no database;
* a read-only root, a `/tmp` that only root can write, `no-new-privileges`,
  a pids limit of 128 (a number from what its slots need up to four times
  that) and a memory limit of 6 GiB;
* `ipc: none` and four sysctls (`kernel.shmmax` 0, `kernel.msgmni` 0,
  `kernel.sem` `0 0 0 0`, `fs.mqueue.queues_max` 0), so a child can create
  no shared memory, message queue or semaphore set that outlives it (see
  below);
* `init: true`, so the processes the worker kills are reaped;
* user `0:10001` with `cap_drop: [ALL]` and only `KILL`, `SETGID` and
  `SETUID` added. It is root because it gives every child a user of its
  own (next section) and must be able to stop that user's processes. It
  parses nothing itself: it moves bytes, bounded, between the socket and
  a child's pipes. It refuses to start with any other capability, without
  `no-new-privileges`, as PID 1, with a pids limit that is absent, cannot
  hold its slots or is more than four times what they need, or in a
  container that lets a child leave state behind;
* one volume, `analysis-socket`: a tmpfs owned by root, group `10001`, mode
  `0750`. `api`, `cron`, `collector` and `lab-triage` (user `10001`, the
  group) mount it read-only and can pass through it to the socket, which is
  mode `0660`.
  No child's user can even enter it.

### What a compromised child can and cannot do

A parser exploit runs as a child of the worker. Slot N of the worker runs
its child as uid `10100 + N` (gid the same, no supplementary group, no
capability), so:

* it cannot unlink, bind or connect to the worker's socket, and it cannot
  signal, trace or read the memory of the worker or of another slot's
  child. That does not depend on the host's `kernel.yama.ptrace_scope`: the
  uids differ and the child holds no capability, so no setting lets it in.
  (Under `--shared-uid`, which is development only, every child shares the
  worker's uid, a scope of `0` would let one read a concurrent request's
  payload, and the readiness row fails);
* a task limit of 16 processes and threads is set on its uid before its
  program starts, so it cannot spend the container's pids and leave the
  worker without a thread for anybody else, and a child that forks until
  it is stopped is stopped at 16;
* it ranks first for the kernel's out-of-memory killer, so when the
  container's memory runs out the kernel kills a child and not the worker;
* before the request is answered every process of that uid is killed, so
  what it detached with `setsid` does not outlive its request, whether or
  not the helper kept the child's stdout. The kill comes before anything
  waits on the child's pipes: until 2026-10-03 it came after, and a helper
  that kept a pipe open wedged the request for as long as it lived, which
  cost the slot for good and left no signal but the readiness row. A slot
  whose uid cannot be emptied, or whose emptying fails, is retired, and with
  none left the worker exits so that Docker restarts it clean;
* it can create nothing that outlives its request. SysV shared memory used to
  survive every process of its uid, count against the container's memory
  limit and be readable by a child of another slot, so that a few requests
  were enough to fill the limit and have the worker killed for it; POSIX
  shared memory (`/dev/shm`), POSIX message queues and files in `/tmp` did
  the same, and the worker, which holds no capability that overrides
  ownership, could remove none of it. `ipc: none` leaves the container no
  `/dev/shm`, the sysctls leave a child unable to create a segment, a queue
  or a semaphore set, and `/tmp` is a tmpfs of root's with mode `0755`, so no
  child's user can write in it (nothing a child runs writes there). The
  worker reads each of these from its own process, refuses to start unless
  they hold, and the readiness row fails when its hello says one is open.

What remains:

* The uids `10100` to `10115` must own nothing else on the host, a second
  analysis worker included. The task limit counts a uid's processes over the
  whole host, not per container, so a second worker would spend the first
  one's 16.
* The container's settings are what keep a child from leaving state behind,
  and the worker can only read that they are set, not that the runtime
  honours them. A kernel keyring is the one other object a plain user can
  leave; Docker's default seccomp profile refuses it, and a container
  started with no seccomp profile is outside this claim.
* Where there is no uid to empty, the local runner (development, and
  `NOCTORNAL_ANALYSIS_LOCAL=1`) stops the child's process group, but a
  helper that left the child's session keeps the child's pipes and lives on.
  The run no longer waits for it (it is answered after five seconds at most)
  and nothing it writes afterwards reaches the answer, but the process stays
  until it exits or is killed.
* A kernel or container-runtime escape from the worker's container is not
  addressed, and a compromised child can still return false findings,
  which the application validates by shape only.

| Variable | Set on | What it does |
|---|---|---|
| `NOCTORNAL_ANALYSIS_SOCKET` | the worker, `api`, `cron`, `collector`, `lab-triage` | the socket the worker listens on and the others connect to |
| `NOCTORNAL_ANALYSIS_WORKER_CONCURRENCY` | the worker | requests run at once, 1 to 16 (default 2); others wait up to 30 seconds for a slot. The service's `pids_limit` must hold 40 plus 20 a slot and be at most four times that, and the worker refuses to start when it is not |
| `NOCTORNAL_ANALYSIS_WORKER_MAX_BYTES` | the worker | the largest request it reads (default `1GiB`); it must hold a sample at the analysis maximum plus a compiled YARA build, and readiness says when it cannot |
| `NOCTORNAL_ANALYSIS_LOCAL` | nowhere, by default | `1` runs analysis in a local child instead, beside this deployment's secrets |

**When it is down, nothing falls back.** A triage pass prints `refused:`
and exits 1, leaving the queue as it was; an analyst's "run it now" waits
for the next pass; a forum poll is refused before its first request, with
the reason on the run. A worker that fails in the middle of a pass is the
sandbox's state and not the sample's or the forum's: the run goes back to
the queue at the same attempt, a compile keeps its attempts, and a poll
ends BLOCKED with no failure counted and no parser drift, keeping its
cursor so the next poll reads the same pages again (the pages it fetched
are not stored). The pass stops and exits 1 saying `interrupted=1`. A
worker that answers but refuses every request, for example because
`NOCTORNAL_ANALYSIS_WORKER_MAX_BYTES` is below a sample, therefore costs
one failed run row a pass, saying the worker refused it, and the same
request is queued again at the same attempt: nothing is lost and no
attempt is spent, and the readiness row says why.

The readiness row `sample_static_analysis` goes red and says why. A
production deployment with no `NOCTORNAL_ANALYSIS_SOCKET` behaves the same
way: the console starts, and analysis is refused until the socket is set. A
setting that is set and unusable (a relative path, or both variables at
once) is refused at start, by name. Asking the worker is remembered for
five seconds and asked by one caller at a time, so a worker that accepts
and never answers costs one wait of at most ten seconds, not one per forum
source in a list.

`NOCTORNAL_ANALYSIS_LOCAL=1` is the explicit way out, for a host that cannot
run the worker: analysis runs in local children again, and the readiness
row stays red, saying so. It is a decision about where hostile bytes are
parsed, so write down who took it.

**Memory.** Each running request holds its payload once while it arrives
(a 256 MiB request peaked the worker at 286 MiB, measured on 2026-10-03), a
child bounded by `NOCTORNAL_SAMPLE_ANALYSIS_MEMORY` (2 GiB of address space
by default) and its output (8 MiB for a step, up to 256 MiB for a compile).
Two YARA scans at their worst, a 256 MiB sample plus a build of up to
256 MiB each, are 2 x (512 MiB + 2 GiB + 8 MiB), about 5.2 GiB, and 6 GiB
holds that. Two 512 MiB requests at once, as hash steps, peaked the worker
at 1.03 GiB and the container at 2.6 GiB. With a 160 MiB limit a child that
outgrew it was killed twice, both requests were answered as crashed steps,
and the worker kept serving. The limit stops holding where the
application's own are raised: `NOCTORNAL_ANALYSIS_WORKER_MAX_BYTES` above
its default, a larger sample cap or a higher concurrency. Raise the
service's `mem_limit` with them.

Confirm it after every change to Docker or to this file:

```sh
docker compose -p noctornal-prod -f infra/production/compose.yml exec analysis-worker \
  python -m noctornal_api.analysis_worker --check        # exit 0: it answers
docker inspect noctornal-prod-analysis-worker-1 --format \
  '{{.HostConfig.NetworkMode}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.CapAdd}} {{.Config.User}} {{.HostConfig.Init}}'
# none true [ALL] [CAP_KILL CAP_SETGID CAP_SETUID] 0:10001 true
# (an older Docker prints the three without the CAP_ prefix)
docker inspect noctornal-prod-analysis-worker-1 --format \
  '{{.HostConfig.IpcMode}} {{.HostConfig.Sysctls}} {{.HostConfig.PidsLimit}}'
# none map[fs.mqueue.queues_max:0 kernel.msgmni:0 kernel.sem:0 0 0 0 kernel.shmmax:0] 128
docker compose -p noctornal-prod -f infra/production/compose.yml exec -u 10100:10100 analysis-worker \
  python -c "open('/tmp/x', 'w')"
# must FAIL with "Permission denied": a child's user can write nothing there
docker compose -p noctornal-prod -f infra/production/compose.yml exec analysis-worker \
  python -c "import socket; socket.create_connection(('192.0.2.1', 443), 3)"
# must FAIL with "Network is unreachable": 192.0.2.1 is a documentation
# address nothing routes, so this sends nothing anywhere
docker compose -p noctornal-prod -f infra/production/compose.yml exec -u 10100:10100 analysis-worker \
  python -c "import os; os.unlink('/run/noctornal-analysis/worker.sock')"
# must FAIL with "Permission denied": a child's user cannot touch the socket
docker compose -p noctornal-prod -f infra/production/compose.yml exec analysis-worker env
# only PATH, HOME, HOSTNAME, the python image's own variables and
# NOCTORNAL_ANALYSIS_*
```

The readiness row asks the worker the same questions itself, and asks the
running process rather than reading this file: the names in its
environment, its network interfaces, its user and capabilities,
`no-new-privileges`, a read-only root, how it keeps its children apart and
the task limit it gives them, its pids limit (a number from what its slots
need up to four times that), the state a child could leave behind, any slot
it has retired (a worker that has lost one is running at reduced capacity),
its parser versions (they must be the API's, so rebuild both together) and
the largest request it takes. It runs the child's selftest through the
worker as well, which must not reach the database host. Every one of those
it does not report, or reports wrong, fails the row.

What was shown with docker, and what was not. The network and environment
checks above were shown on 2026-10-02, and everything else on 2026-10-03,
with the `noctornal-api:0.5.2` image and this tree's code mounted read-only
(a 0.7.1 image needs a package index to build). Against the worker as
`compose.yml` starts it: a child that exhausts the pids, a child that
forks a hundred helpers and hangs, a child that detaches processes into a
new session, a child that tries to replace the worker's socket, and one
slot's child reading another's memory. None of them stopped the worker,
left a process behind, or replaced the socket. The worker refused to start
in each of five shapes that differ from `compose.yml`, and a selftest and
a PE step ran through it as uid `10100` with no capability, a task limit
of 16 and the highest OOM score (the image has no `pefile`, so the step
answered with that gap). Not shown: a build of the 0.7.1 image under the
worker's environment allow-list (a base-image bump that adds a variable
shows as a refused worker, by name, in its log), forum parsing inside a
container (the image has no `selectolax`), and the host's `ptrace_scope`
at `0`, which is a host setting this work does not change.

The 2026-10-03 verification round, in containers started as `compose.yml`
now starts them (the same image and mounted code). A child that detaches a
helper which keeps its stdout, started with `setsid` or without, used to
leave its request unanswered for ninety-five seconds, the helper alive and
the slot lost, and two such requests left every later request answering
`worker_busy` while the health check stayed green. Now both requests are
answered in 0.3 seconds, a third request in 0.2, and no process of a child's
user is left. A compromised child that tried to create SysV shared memory
(200 MiB), a semaphore set, a message queue, POSIX shared memory, a POSIX
queue and files in `/tmp` and `/dev/shm` succeeded at all of them under the
old container settings (the segment stayed after the request, and a later
request on another slot could use it) and at none under the current ones
(`EINVAL`, `ENOSPC`, `ENOENT` and permission denied). The worker refused to
start, by name, with default IPC, with the sysctls missing, with a `/tmp`
every user could write, with no pids limit (the host's own, 38393, is above
the ceiling) and with a limit of 100000, and started with the settings as
they are, reporting a pids limit of 128 and nothing open.

---

## The collector: the one service that holds the persona key

Since 2026-10-02 the API cannot open a collection persona's credential. A
persona credential (a Telegram session, a forum login) is sealed under its
own key, `NOCTORNAL_PERSONA_KEK`, and the only service that holds it is
`collector`: it runs every persona act the console asks for (a Telegram
chat looked up, joined, checked, marked as a member chat or rebound, and a
Poll now of a source a persona reads) and the scheduled collection polls.
The API queues an act in the database and answers with its outcome, or
with "queued" while the collector has not finished it; the console follows
it under Feeds, Persona acts. The cron loop no longer polls.

```sh
python3 -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
cp infra/production/collector.env.example infra/production/collector.env
sudo chown root:root infra/production/collector.env
sudo chmod 600      infra/production/collector.env
```

Put the key in `collector.env` and nowhere else, never in `secrets.env`. The
services that run the application's code (the API and the sample origin, the
cron loop, the Lab workers, the embedding pass) and the egress proxy refuse
to start if they find it. The database, the object store, Redis, the
migration job and Caddy run none of that code and check nothing: they read
`secrets.env`, so a key put there would simply be carried. The collector
refuses to start without it, by name, **whether or not the deployment has a
persona**. The collector also
runs every scheduled poll (the cron loop no longer polls), so a deployment
without `collector.env` polls **nothing at all**, the feeds no persona reads
(RSS, a plain site) included. That is red on the readiness register (below),
not silent. Enrolling a Telegram persona needs the key too, so it runs in the
collector:

```sh
docker compose -f infra/production/compose.yml run --rm collector \
    python scripts/telegram_persona.py enrol --persona <persona id>
```

### Upgrading any existing deployment

1. Create `collector.env` as above **before** `docker compose up -d`, even
   if no persona has ever been enrolled. Without it the collector exits at
   once, names the missing key, and compose restarts it in a loop, and in
   the meantime nothing is polled.
2. If the deployment has personas: their credentials, enrolled before
   2026-10-02, are sealed under the TOTP key. Until they are moved the
   collector refuses them by name, their polls are BLOCKED with that
   sentence, and the readiness row `collector_split` counts them. Move them
   once, in the collector, which holds both keys:

```sh
docker compose -f infra/production/compose.yml run --rm collector \
    python scripts/rewrap_secrets.py --persona            # report
docker compose -f infra/production/compose.yml run --rm collector \
    python scripts/rewrap_secrets.py --persona --apply    # move
```

3. Rebuild the image (`up -d --build`) and remove the old one. An image
   built before 2026-10-03 carries whichever env files sat beside
   `compose.yml` when it was built (`secrets.env` aside, the egress files,
   `postgres-init.env`, and `collector.env` once it existed), in every layer.
   If such an image ever left this host, treat what those files hold as
   exposed and rotate it.

### What the register says about the collector

The collector writes a heartbeat to the database when it starts and every
30 seconds while it runs, with what its key ring made of the persona
credentials it sampled (counts and key ids, never a key). The readiness row
`collector_split` reads it, so it is red, with the action, when:

* no collector has ever started against this database (an upgrade without
  `collector.env`: an empty queue and nothing polled);
* no collector has been seen for ten minutes (a stopped or crash-looping
  service, which is also every scheduled poll stopped);
* the collector's persona key does not open the credentials it sampled when
  it started (a wrong or restored-from-the-wrong-backup `collector.env`; a
  persona whose key changed under its id fails each act by name until the key
  is restored, named in `NOCTORNAL_PERSONA_KEK_RETIRED` under its own id, or
  the persona is enrolled again);
* a persona act has waited more than two minutes in the queue;
* persona credentials are still sealed under the TOTP key;
* the API holds the persona key.

`docker compose stop collector` is safe at any time: it finishes the act in
hand and claims no other, within the 180 second `stop_grace_period`.

---

## Day-to-day

**Logs.** Everything logs to stdout.

```sh
docker compose -p noctornal-prod -f infra/production/compose.yml logs -f api
docker compose -p noctornal-prod -f infra/production/compose.yml logs -f cron
```

The cron container prints a timestamped start and exit code for each pass.
`notify_drain` exits 1 when a delivery failed in that pass (information,
not a reason to stop draining), so a persistent non-zero every five minutes
is the thing to look at. The failed deliveries are in the ledger with their
reasons at `GET /api/v1/notifications/deliveries?refused_only=true`.

**Updating.** Pull the code, bring the secrets files to the new release,
then rebuild and restart. The migration job runs again on every `up`, so a
release carrying migrations applies them before the API starts:

```sh
git pull
sudo ./release/install.sh --production-secrets
docker compose -p noctornal-prod -f infra/production/compose.yml up -d --build
```

The middle step changes nothing when there is nothing to change. From a
release before 2026-10-02 it is required: see [Upgrading](#upgrading) and
[release/secrets-upgrade/README.md](../../release/secrets-upgrade/README.md).

On a host whose `umask` is `077`, a pull leaves the files it writes `0600`,
which a container that does not own them cannot read: run the mode check from
[step 4](#4-start-it) before the `up`. Coming from a tree older than
2026-10-03, also know that every container now drops its capabilities, so
`Caddyfile`, `mc-alias.sh`, `tls/public.crt` and `db/init` must be readable by
`other` (the check says so), and `tls/private.key` must be root's, mode 600.

Every image the stack pulls is pinned by digest (Hardening, below), so an
update that changes one arrives as a change in this repository, never from a
registry's idea of what a tag means today.

A restart waits for the passes in progress. The cron, lab-triage, lab-cron
and embed-pass services stop their loops on the stop signal, let the job that
is running finish (a persona poll, a sandbox send, an email), and start no
other; compose gives each up to 5 minutes 30 seconds before it kills one.
That is why an `up -d --build` can take a few minutes on a busy host.

**Backups, nothing here does this for you.** Three things must be copied
off this host, together: the database, the evidence and raw buckets, and
the env files beside the compose file (`secrets.env`, `caddy.env`,
`postgres-init.env`, `migrate.env` and the two egress files). Without the
buckets a restore gives you a case file whose exhibits are missing; without
`secrets.env` it gives you one whose sealed columns never open again
(step 1).

**Where a backup goes matters as much as having one.** A dump is the whole
case database in plaintext: every assertion, document, note and audit row and
every TLP:AMBER_STRICT and RED row, with only the sealed columns as
ciphertext, and `pg_dump` runs as the owner role, which row-level security
does not bind. The mirrored exhibits and raw captures are plaintext as well.
So a backup is the most sensitive file on this host, and three rules hold:

* **Outside the checkout.** The repository root is the Docker build context,
  so a dump written there is baked into every container by the next
  `up -d --build`, and `git add -A` would stage it. `.dockerignore` and
  `.gitignore` refuse the usual names (`*.sql`, `*.dump`, `noctornal-*`) as a
  net under this, and a test holds them; the net is not the plan.
* **Private from the first byte.** A directory only root can enter, and
  `umask 077` in a subshell that writes (and in the script inside the
  container that runs `mc`), so no file is ever created readable by anyone
  else. It is a subshell on purpose: a `umask 077` left in your own shell
  would make the next `git pull` or certificate you create unreadable to the
  containers (see step 4).
* **Encrypted before it reaches a disk.** The dump goes through `age` in the
  same pipe. With a public key this host holds only the recipient's public
  half and cannot decrypt its own backups; keep the private half, with the
  copy of `secrets.env`, somewhere that is not this host. `gpg --symmetric`
  with `--passphrase-file` (a file mode 0600, never `--passphrase`, which is
  a command-line argument) does the same job where `age` is not installed.
  The mirrored objects are not encrypted by anything here: keep that
  directory on an encrypted volume.

```sh
(   # a subshell, so the umask and pipefail end with it and never reach the
    # shell you build, pull and edit files in afterwards
  set -o pipefail    # bash: a failed pg_dump must fail the pipe, not leave a short file
  umask 077
  install -d -m 0700 /srv/noctornal-backup

  # The database: custom format, encrypted in the pipe, never plaintext on disk.
  # BACKUP_RECIPIENT is the age public key (age1...) of whoever will restore.
  docker compose -p noctornal-prod -f infra/production/compose.yml exec -T postgres \
    sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -Fc -h 127.0.0.1 -U noctornal noctornal' \
    | age -r "$BACKUP_RECIPIENT" \
    > /srv/noctornal-backup/noctornal-$(date -u +%Y%m%dT%H%M%SZ).dump.age

  # The object store. Evidence AND raw captures: an exhibit restored
  # without the capture it was derived from has lost half of what makes it
  # an exhibit. /srv/noctornal-backup is yours to choose, and must be the
  # 0700 directory made above, outside this checkout.
  docker compose -p noctornal-prod -f infra/production/compose.yml \
    run --rm --no-deps -v /srv/noctornal-backup:/backup \
    --entrypoint /bin/sh minio-init -c '
      set -e
      umask 077
      . /mc-alias.sh
      mc_setup
      mc mirror --overwrite "local/$EVIDENCE_BUCKET" /backup/evidence
      mc mirror --overwrite "local/$INGEST_BUCKET" /backup/raw'
)
```

The dump is in custom format, so it is restored with `pg_restore`, not
`psql`. Nothing here verifies a backup: restore one on a scratch host before
you rely on it.

The second command runs `mc` in a one-off container of the `minio-init`
service, because that service already has what `mc` needs: the compose
network (MinIO publishes no port), the root credentials and bucket names
from `secrets.env`, the certificate from step 3, and `mc-alias.sh`, which
gives `mc` the root credential through its environment and trusts that
certificate. The credential is deliberately not an argument of any command,
because an argument is readable by every local account on the host for as long
as its process lives. The alias lives and dies with that container; nothing
on the host defines one.

**The samples bucket is left out on purpose.** It holds live malware,
encrypted, and a mirror of it escapes whatever
`NOCTORNAL_REJECTED_SAMPLE_DISPOSITION` decided. Under `destroy`, a
rejection deletes the bytes, and the mirror keeps them where the rejection
cannot reach. Under `preserve`, the default, a rejection moves the bytes
into the preservation bucket under a legal hold and deletes the working
copy, and the mirror keeps a copy outside that hold and outside the
two-person retrieval. Copy it only if counsel has said to, and to
somewhere the rejection procedure covers.

**Whether `noctornal-preserved` belongs in a backup is for counsel too.**
It holds rejected malware under a legal hold that nothing in the product
lifts, and the database keeps the data key that opens each object, so a
copy of that bucket beside the dump and `secrets.env` is a readable copy
of the malware, outside the hold. If counsel says to keep one, add a third
mirror to the quoted script, after the raw one and before the closing
quote:

```sh
    mc mirror --overwrite "local/${PRESERVE_BUCKET:-noctornal-preserved}" /backup/preserved
```

Know what it does not carry. A mirror to disk keeps the bytes only: not
the legal hold, and not the object version each preserved sample's row
names, which is the version a retrieval reads. Nothing in this release
restores one.

Copy the env files every time you copy the database, and keep them as
carefully as the dump: together they open every sealed column except a
collection persona's credential, and `migrate.env` holds the owner's DSN.
A persona's credential opens only with the persona key in `collector.env`,
which the dump and `secrets.env` do not carry: back it up with them,
somewhere that is not this host (a restore without it loses every persona,
which must then be enrolled again; nothing else is affected), and keep it
apart from them if you want the split to mean anything for a stolen backup.

**Stopping.**

```sh
docker compose -p noctornal-prod -f infra/production/compose.yml down
```

Never add `-v` to that unless you mean it. It destroys `prod-pgdata` (the
case file), `prod-miniodata` (the evidence) and `caddy-data` (the ACME
account and every issued certificate, and issuance is rate-limited per
hostname per week). The evidence bucket's objects are written under a
COMPLIANCE object lock, which nobody can lift, including the root
credential: destroying the volume is the only way to remove them, which is
the property evidence is supposed to have.

---

## Upgrading

### From a release before 2026-10-02: the owner's credential and Redis

[release/secrets-upgrade/README.md](../../release/secrets-upgrade/README.md)
is the whole procedure, with what stops and what it says. In short, two
things moved, and an existing deployment that is not brought along stops
at boot, on purpose and with a sentence saying how to fix it:

* `POSTGRES_PASSWORD` and `NOCTORNAL_MIGRATION_DATABASE_URL` left
  `secrets.env` (`docs/17` F52). The migrate job now reads `migrate.env`
  alone and refuses without it. Every other service holds both blank
  whatever `secrets.env` says, and the API and the cron jobs refuse to run
  holding either.
* Redis runs an ACL with the default user disabled, so a `REDIS_URL`
  naming the bundled `redis` service must sign in as `noctornal_limiter`.
  The `redis` service refuses to start while it does not.

One command does both, before `up`, with `sudo` because the files are
root's, mode 600:

```sh
git pull
sudo ./release/install.sh --production-secrets      # release\install.ps1 -ProductionSecrets on Windows
docker compose -p noctornal-prod -f infra/production/compose.yml up -d --build
```

It moves the two lines out of `secrets.env` into `postgres-init.env` and
`migrate.env` (creating them from their templates if they are not there),
keeps the Redis password if it is URL-safe and rewrites `REDIS_URL` to sign
in with it as `noctornal_limiter`, and prints what it did by name, never by
value. A destination that already holds a different owner password is a
refusal, and nothing is written: keep the one the database was initialised
with, delete the other line, and run it again. So is a file it may not
read, in one sentence naming the file: run it with `sudo`.

**The way back.** Before it changes a file it copies it to
`NAME.backup-UTCSTAMP` beside it, mode 600, gitignored and kept out of the
image. To return to the previous release, copy each backup over its file
and check that release out; the new compose file refuses the old layout
by design, so both have to go back together:

```sh
cd infra/production
for f in secrets.env postgres-init.env migrate.env; do
  [ -f "$f.backup-STAMP" ] && cp -p "$f.backup-STAMP" "$f"
done
```

A `migrate.env` the command created has no backup and is simply unused by
the older release. Nothing in the database changes in either direction.

---

## Retention sweep

Collected documents (a Telegram group's messages, a forum's posts) carry a
retention clock, and nothing in this stack destroys them when it runs out
unless somebody runs the sweep. The console's purge is case-scoped and a
collected document belongs to no case, so it never reaches them.

The sweep is `scripts/retention_sweep.py`, and it is **not in the cron loop**:
no compose service, installer or launcher runs it. It destroys third-party
personal data, so who runs it, how often and under which authority is the
owner's decision (`docs/16` L4), and a purge that runs itself on a timer
nobody watches is how data disappears on a Sunday. What keeps the gap from
going quiet is the readiness row `retention_sweep_current`: it turns red when
a document no hold keeps has been past its clock for more than seven days, and
it counts them without naming one.

It destroys collected documents past their clock that nothing holds, by the
same purge the other families use. A hold on the document or on any version of
it, a case under legal hold that cites any version, and an unretracted
assertion that rests on it each keep a document, and a hold placed while a
sweep runs wins. Exhibits, ingest records, lookups and dead letters are not
touched: they keep the case-scoped route in the console.

**Look first.** A dry run is the default. It changes nothing, writes nothing
and needs no declaration. The one line it prints counts what is past its
clock, what a hold keeps and what a sweep would destroy:

```sh
docker compose -p noctornal-prod -f infra/production/compose.yml \
  run --rm --no-deps cron /bin/sh -c '
    cat /etc/ssl/certs/ca-certificates.crt /certs/public.crt > /tmp/ca-bundle.crt
    export SSL_CERT_FILE=/tmp/ca-bundle.crt
    python scripts/retention_sweep.py'
# mode=dry-run past_clock=140 sweepable=120 held=20
```

**Then destroy.** The same command with `--apply`, an authority and an account:

```sh
docker compose -p noctornal-prod -f infra/production/compose.yml \
  run --rm --no-deps -e NOCTORNAL_RETENTION_SWEEP_AUTHORITY='RETSCHED-2026-014' \
  cron /bin/sh -c '
    cat /etc/ssl/certs/ca-certificates.crt /certs/public.crt > /tmp/ca-bundle.crt
    export SSL_CERT_FILE=/tmp/ca-bundle.crt
    python scripts/retention_sweep.py --apply --actor you@example.org'
# mode=apply passes=2 documents_purged=120 tombstones=1 held=20 remaining=0
```

A real run needs all three, and refuses with exit 2, destroying nothing,
without any of them:

* `--apply`.
* `NOCTORNAL_RETENTION_SWEEP_AUTHORITY`: a reference an auditor can follow to
  the retention schedule, counsel's instruction or ticket the destruction rests
  on. The software records it on every tombstone and in the audit event, and it
  cannot verify it, exactly as it cannot verify the L1 policy reference
  (`docs/16` L1): a blank, a `replace-me` placeholder, a word such as `true`
  and anything under five characters are refused, and a false reference
  produces a destruction nobody can defend. Pass it with `-e` for the one run
  rather than as a line of `secrets.env`, which every container reads.
* `--actor EMAIL`, or `NOCTORNAL_RETENTION_SWEEP_ACTOR`: an active account that
  holds `retention.purge` (`SYS_ADMIN` and `CASE_OWNER` do). It is recorded as
  who destroyed what on every tombstone. It is a declaration, not a sign-in:
  the script runs on this host with the system database role, where there is no
  session and no step-up, so name your own account, never a colleague's.

The exit code is the only channel a scheduler has back. `0`: the run did what
it was asked (a dry run always). `1`: a real run left documents it could have
destroyed, because the object store refused to delete their markup (the
warnings say which key, never what it held) or the pass limit was reached; read
the warnings and run it again. `2`: it refused to run, for a missing or
placeholder authority, no named account, no store for collected markup (set
`MINIO_ENDPOINT`, `MINIO_ACCESS_KEY` and `MINIO_SECRET_KEY`, or the sweep
cannot delete the markup and will not record a destruction that did not happen)
or a credential in the environment that carries a published value (the check every unattended job makes in production).

What a real run writes: the purge's tombstone for each pass of up to 500
documents (`core.purge_tombstone`, object type `document`, authority
`retention sweep under <your reference>`), the purge's `PURGE_EXECUTED` audit
rows, and one `RETENTION_SWEEP` audit event per run: counts, the reference and
where it ran, never a document, an id or a key. It writes that event when
nothing was due too, so the log shows that a sweep ran. `passes` counts the
last pass, the one that finds nothing left to destroy. A backlog bigger than
one pass is cleared in the one run, up to `--max-passes` (100 by default, so
50,000 documents).

Unlike the console's purge, the script does not ask for a preview digest of an
earlier dry run: the dry run is for you, and the declared authority and the
named account are the record. Place a legal hold before the sweep runs, not
after: a hold cannot bring back what has been destroyed.

**Scheduling it.** Use the host's scheduler, not the compose `cron` service,
whose loop runs every five minutes. A weekly run suits `retention_sweep_current`
(its seven days are that schedule); a deployment whose policy says otherwise
sets its own and accepts the row's wording. For example, from root's crontab
(`sweep.sh` holds the `docker compose run` above, with the reference chosen for
that schedule):

```
17 3 * * 0  cd /opt/noctornal && ./sweep.sh >> /var/log/noctornal/retention_sweep.log 2>&1
```

Whoever schedules it is deciding who destroys third-party data and under which
authority. Settle that with counsel first (`docs/16` L4, `docs/17` F30), and
write the reference so that the person reading a tombstone in a year can find
what it rested on.

---

## Hardening, and what is still open

What `compose.yml` does to every container, and what each one keeps:

| Service | Capabilities kept | Why |
|---|---|---|
| caddy | `NET_BIND_SERVICE` | binds 80 and 443; the binary carries it as a file capability, so without it the container does not start |
| postgres | `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID` | the image's entrypoint prepares the data directory as root and drops to the postgres user |
| redis | `DAC_OVERRIDE` | runs as root over a volume the redis user owns |
| minio, minio-init, and every application service | none | uid 10001 needs none, and MinIO and `mc` run as root without them |

Every container also has `no-new-privileges`, and Caddy's root filesystem is
read-only. Dropping `NET_RAW` from all of them takes the raw socket away from
a compromised container on the shared bridge.

The price is file modes. Without `DAC_OVERRIDE`, root in `caddy`, `minio` and
`minio-init` is an ordinary user to a bind-mounted file: it reads what it owns
or what `other` may read, and nothing else. That is why step 3 states the
modes of `tls/` and `public.crt`, and step 4 checks the rest before `up`. A
checkout made as a non-root operator under a `umask` of `077` fails closed (Caddy
and `minio-init` cannot read their files and do not start), not open.

Caddy sends `Strict-Transport-Security` (a year, subdomains included, no
`preload`) on both hostnames, speaks TLS 1.3 only and does not advertise
HTTP/3, which is not published. The application leaves HSTS to this
terminator, so the Caddyfile is the only place it can come from; a test holds
it there. A client that cannot speak TLS 1.3 cannot reach the console. Under
`NOCTORNAL_TLS_MODE=internal` Caddy logs "failed to install root
certificate" once at start: it tries to add its local CA to the container's
own trust store, which is read-only and which nothing in the container uses.

**Images are pinned by digest**, in `compose.yml` and in the Dockerfile's
`FROM`, because a tag is whatever its registry says it is at pull time. To
move one deliberately:

```sh
docker buildx imagetools inspect caddy:2-alpine        # the digest line is the pin
```

then put `name:tag@sha256:...` in `compose.yml` (the digest alone is what
Docker uses; the tag is for the reader) and rebuild. The pinned base image
does not pick up Debian security updates by itself: move its digest when you
take a new release, and rebuild with `--pull`. `ghcr.io/dboudreau00/minio` is
byte for byte the build `quay.io/minio/minio` served for the same release;
both names resolve to the same digest, which is how that is checked.

**What is still open.** Stated rather than hidden:

* **Caddy still runs as uid 0**, with the capability set above and nothing
  else. `caddy-data` and `caddy-config` already exist on a running deployment,
  owned by root, and a non-root Caddy could not open the ACME account in them.
  To run it unprivileged (Docker 20.10 or later), change the volumes once and
  add `user:` to the caddy service:

  ```sh
  docker compose -p noctornal-prod -f infra/production/compose.yml stop caddy
  docker run --rm -v noctornal-prod_caddy-data:/data -v noctornal-prod_caddy-config:/config \
    --entrypoint chown caddy:2-alpine -R 10002:10002 /data /config
  # then, under `caddy:` in compose.yml:   user: "10002:10002"
  ```
* **Caddy still has a route out** (`edge`, for ACME) and shares a bridge with
  Postgres, Redis and MinIO. It is the TLS terminator, not a service the egress
  proxy fronts.
* **The Postgres and Redis hops are plaintext** inside the compose network. Only
  MinIO is TLS here, on the argument that a replayable request signature must
  not cross the wire. With `NET_RAW` gone a compromised container cannot sniff
  the bridge, but it has not been made impossible: enabling `sslmode` on Postgres
  and TLS on Redis is open work.
* **`./tls`, with MinIO's `private.key`, is mounted into every application
  container.** Only `public.crt` is needed there; the host's `chmod 600` on the
  key is what protects it from the application user. Splitting it into a CA
  directory is open work.
* **No read-only root filesystem, and no memory or process limits, on the
  application services.** The CA bundle and the Lab's child processes write to
  `/tmp`, which has not been proved under a tmpfs, and the limits need a sizing
  for your host.
* **Two MinIO service-account secrets are still arguments** of
  `mc admin user svcacct add`, once, the first time each account is created
  (the `SAMPLE_` and `PRESERVE_` keys; the root credential and the database role
  passwords are not). Mount `/proc` with `hidepid=2` on the Docker host if it
  has other local accounts. The command's own output, which echoes the new
  secret key, is discarded, so the key is not in the `minio-init` container log.
* **The build context is the checkout, not an export of it.** `.dockerignore`
  keeps out everything it names (every `.env` file at any depth, every `*.env`
  file and an editor's copy of one such as `secrets.env.bak`, keys,
  certificates, dumps and backups), and `.gitignore` carries the same set, but
  a file with a name no rule knows still reaches the image, except under
  `infra/production/`, which is left out whole apart from the templates and
  the compose file.
  Building from `git archive HEAD` removes that class, and needs the compose
  file's `context` pointed at the export, which this file does not do.
* **Images and tools that are not digest pinned.** The development stack
  (`infra/docker-compose.yml`) and the CI workflow's service containers pull by
  tag, on purpose: they track what a developer's machine and the suite use, and
  a digest there would only go stale. What each tag resolved to on 2026-10-03,
  for a reader who wants to compare or to pin one:

  | Image (tag) | Pulled by | Digest on 2026-10-03 |
  |---|---|---|
  | `pgvector/pgvector:pg16` | development stack, CI | `sha256:ccc6e83d6e35e931dc7c5def2022729d5a6c370318d099181995567ff1fb4d6b` |
  | `redis:7-alpine` | development stack, CI | `sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499` |
  | `ghcr.io/dboudreau00/minio:RELEASE.2025-04-22T22-12-26Z` | development stack | `sha256:a1ea29fa28355559ef137d71fc570e508a214ec84ff8083e39bc5428980b015e` |
  | `ghcr.io/dboudreau00/mc:RELEASE.2025-08-13T08-35-41Z` | development stack | `sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727` |
  | `axllent/mailpit:v1.31.0` | development stack | `sha256:c96991d9bef73594c246d89ca81411d4e916f03e76a7d2d72fa2ab5dd3c9ce24` |

  The first four are the digests `compose.yml` pins for production, and a test
  holds this table to that file, so moving a production pin without updating
  the table fails the suite. Mailpit is a development mail sink and is not in
  the production stack. The CI workflow's two actions (`actions/checkout@v4`,
  `actions/setup-python@v5`) are pinned by tag and the workflow has no
  `permissions:` block, the installers `pip install` an unpinned `pip`, and the
  Dockerfile installs whatever `gnupg` Debian ships that day (`docs/17` F34
  depends on its version).

---

## What you are NOT getting

* **No high availability.** One host. When it is down, the product is down,
  and there is no failover to anything.
* **No backups.** The volumes are on one disk on this machine. The commands
  above are a manual procedure nothing runs for you, and nothing verifies a
  restore.
* **No audit of this deployment.** The application's own audit chain covers
  what analysts do inside it. Nothing here records who ran `docker compose`,
  edited `secrets.env` or read a volume.
* **No monitoring.** No metrics, no alerting, no log aggregation. The
  readiness register answers when you ask it and tells nobody otherwise,
  nothing anywhere reads its verdict on a schedule.
* **No secrets management.** `secrets.env` is a file on disk in plain text.
  There is no Vault, no KMS, and the TOTP key-encrypting key sits in it.
  Every container built from the application image, except the migrate job,
  the egress proxy and the analysis worker, receives the whole file, and so
  do Postgres, Redis and MinIO. The analysis worker receives none of it.
  Caddy does not: it has `caddy.env`, with its three values. The schema
  owner's credential is the one thing kept out of it (`postgres-init.env`
  and `migrate.env`, each read by one service).
* **`docs/16` L1-L5 are unresolved.** Prohibited content in the sample
  store, stealer logs and third-party personal data at scale, persona
  operation and computer-misuse exposure, message content capture, and
  active capture of attacker infrastructure. Every one of them is a
  question for counsel, this file settles none of them, and a green
  readiness register does not either.
