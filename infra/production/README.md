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
(0)`. Everything else should be `running`, and `api` and `sample-origin`
should reach `healthy`.

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

Forty-four checks, each with the evidence behind it and, when it fails, the
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

Four of the forty-four are **blocking** (`readiness.BLOCKING_CHECKS`):
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
  Every container built from the application image receives the whole file,
  and so does Caddy, which needs three of its variables.
* **`docs/16` L1-L5 are unresolved.** Prohibited content in the sample
  store, stealer logs and third-party personal data at scale, persona
  operation and computer-misuse exposure, message content capture, and
  active capture of attacker infrastructure. Every one of them is a
  question for counsel, this file settles none of them, and a green
  readiness register does not either.
