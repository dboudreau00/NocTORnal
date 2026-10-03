# Production deployment: one host, docker compose

This directory is the whole deployment: a reverse proxy, Postgres, Redis,
MinIO, the API, a second process serving the sample origin, and a cron
loop. There is no Kubernetes here and no cloud service; the target is one
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
  from the repository root.

Counsel has work to do before an analyst signs in. See
[What stays red, and what a red check refuses](#what-stays-red-and-what-a-red-check-refuses).
Doing it after the stack is up is fine; doing it after the first ingest is
not, and the collection route refuses to poll until it is done.

---

## 1. Write the secrets file

```sh
cp infra/production/secrets.env.example infra/production/secrets.env
```

`secrets.env.example` is the reference for every variable: what it is, and
what breaks when it is wrong. Work through it top to bottom. Nothing in the
stack checks that you replaced the placeholders, and several of them fail
quietly rather than loudly.

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
account's TOTP secret, each persona's collection credential, each stored
victim credential and the data key of every sample, preserved samples
included. A database restored without the key that sealed it opens none
of them: no enrolled account can complete a sign-in (it answers 503), and
no persona credential, victim credential or sample can be read again.
Nothing recovers them short of the key, so back it up with every backup of
the database, somewhere that is not this host. Rotating it loses nothing:
the envelope keeps a ring (`NOCTORNAL_TOTP_KEK_RETIRED`, see the
template), the readiness check `kek_ring_opens_stored_secrets` says
whether every stored secret still opens, and
`scripts/rewrap_secrets.py --apply` moves them under the new key.

Then lock the file down. It holds every password in the deployment:

```sh
sudo chown root:root infra/production/secrets.env
sudo chmod 600      infra/production/secrets.env
```

> `docker compose config` prints this file's contents, resolved into each
> service's environment. Do not paste that output into a ticket.

---

## 2. Check the two passwords that are written twice

`POSTGRES_PASSWORD` also appears inside `NOCTORNAL_MIGRATION_DATABASE_URL`,
and `NOCTORNAL_APP_DB_PASSWORD` also appears inside `DATABASE_URL`. Nothing
compares them. A mismatch surfaces on first boot as the migration job
failing to authenticate, which reads like a bug in the migration.

There are two Postgres roles on purpose. `noctornal` owns the schema and is
the only thing that ever runs Alembic. `noctornal_app` is least privilege,
is not the owner, and cannot `ALTER TABLE ... DISABLE TRIGGER`, which is
precisely what a compromised API process would want in order to write
around the audit and custody chains. The app role is created by
`db/init/10-app-role.sh` **at initdb**, and initdb scripts run once against
an empty data directory: changing `NOCTORNAL_APP_DB_PASSWORD` later does
nothing to an existing cluster, and you have to `ALTER ROLE` by hand.

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
sudo chown root:root infra/production/tls/private.key
sudo chmod 600       infra/production/tls/private.key
```

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

While `iam.app_user` is empty (and only then) one unauthenticated route
creates the first administrator. It hands out `SYS_ADMIN`,
`SECURITY_OFFICER`, `CASE_OWNER` and `ANALYST`, which is right for a
single-operator install and clears the two account-shaped readiness items
in one call, `security_officer_present`, which is blocking, and
`sys_admin_present`, which is not. It answers 409 forever afterwards, and
it counts every row, active or not.

```sh
curl -sS -X POST https://YOUR-CONSOLE-HOSTNAME/api/v1/setup/first-admin \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.org","display_name":"Your Name"}'
```

Add `-k` while `NOCTORNAL_TLS_MODE=internal`: those certificates come from
Caddy's own CA and nothing public trusts them.

**The credentials come back once and are not retrievable.** Save them, then
sign in at `https://YOUR-CONSOLE-HOSTNAME/ui` and enrol your authenticator.

If the route is not reachable for some reason, the same job can be done
from a container:

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

Forty-three checks, each with the evidence behind it and, when it fails, the
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

Four of the forty-three are **blocking** (`readiness.BLOCKING_CHECKS`):
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
counts keys in the limiter's Redis that are not under its `rl:` prefix, and
keys in that instance's other databases, without reading a value; it is
green on this compose file's Redis, which nothing else uses.

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
service and Caddy receive. They are in three files beside it:

| File | Read by | Holds |
|---|---|---|
| `egress-proxy.env` | the egress proxy alone | its database URL, the client key, the seal key, the fingerprint key |
| `egress-client.env` | api and cron | the client key, the fingerprint key, the seal key's public half |
| `postgres-init.env` | postgres alone | `NOCTORNAL_EGRESS_DB_PASSWORD`, for `db/init/20-egress-role.sh` |

```sh
python scripts/egress_setup.py keygen     # prints every key, once
cp infra/production/egress-proxy.env.example infra/production/egress-proxy.env
cp infra/production/egress-client.env.example infra/production/egress-client.env
cp infra/production/postgres-init.env.example infra/production/postgres-init.env
python scripts/egress_setup.py preflight  # checks all three before you start
```

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
no such child runs in `api`, `cron` or `lab-triage`. They hand each read
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
  `0750`. `api`, `cron` and `lab-triage` (user `10001`, the group) mount it
  read-only and can pass through it to the socket, which is mode `0660`.
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
| `NOCTORNAL_ANALYSIS_SOCKET` | the worker, `api`, `cron`, `lab-triage` | the socket the worker listens on and the others connect to |
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

**Updating.** Pull the code, then rebuild and restart. The migration job
runs again on every `up`, so a release carrying migrations applies them
before the API starts:

```sh
git pull
docker compose -p noctornal-prod -f infra/production/compose.yml up -d --build
```

**Backups, nothing here does this for you.** Three things must be copied
off this host, together: the database, the evidence and raw buckets, and
`secrets.env`. Without the buckets a restore gives you a case file whose
exhibits are missing; without `secrets.env` it gives you one whose sealed
columns never open again (step 1).

```sh
# The database.
docker compose -p noctornal-prod -f infra/production/compose.yml exec -T postgres \
  sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -h 127.0.0.1 -U noctornal noctornal' \
  > noctornal-$(date -u +%Y%m%dT%H%M%SZ).sql

# The object store. Evidence AND raw captures: an exhibit restored
# without the capture it was derived from has lost half of what makes it
# an exhibit. /srv/noctornal-backup is yours to choose.
docker compose -p noctornal-prod -f infra/production/compose.yml \
  run --rm --no-deps -v /srv/noctornal-backup:/backup \
  --entrypoint /bin/sh minio-init -c '
    set -e
    mkdir -p /root/.mc/certs/CAs
    cp /certs/public.crt /root/.mc/certs/CAs/minio.crt
    mc alias set local https://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null
    mc mirror --overwrite "local/$EVIDENCE_BUCKET" /backup/evidence
    mc mirror --overwrite "local/$INGEST_BUCKET" /backup/raw'
```

The second command runs `mc` in a one-off container of the `minio-init`
service, because that service already has what `mc` needs: the compose
network (MinIO publishes no port), the root credentials and bucket names
from `secrets.env`, and the certificate from step 3, which `mc` trusts
only once it is copied into its own CA directory. The alias it sets lives
and dies with that container; nothing on the host defines one.

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

Copy `secrets.env` every time you copy the database, and keep it as
carefully as the dump: together they open every sealed column.

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
  Every container built from the application image receives the whole file
  except the analysis worker, which receives none of it, and so does Caddy,
  which needs three of its variables.
* **`docs/16` L1-L5 are unresolved.** Prohibited content in the sample
  store, stealer logs and third-party personal data at scale, persona
  operation and computer-misuse exposure, message content capture, and
  active capture of attacker infrastructure. Every one of them is a
  question for counsel, this file settles none of them, and a green
  readiness register does not either.
