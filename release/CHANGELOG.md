# Changelog

## Alpha 6: 2026-09-24

Everything since Alpha 5.2, ending in a review, the rest of that review's
findings, and the checks before tagging. The work of September comes
first: the program can be deployed as a service (`infra/production`), the
API can run as a database role that cannot switch off the audit
triggers, the console holds no credential, roadmap items 8 to 12 landed
(item 13's scheduler is the Wave 1 cron, and its adapters stay unbuilt),
and the documentation was cut to what is true. Then the 2026-09-22 review
of the console and the code behind it, which verified 229 problems. The
first fixes took 75 of them, all twelve criticals among them, and a
second review of those fixes found 43 more, all fixed. The release checks
then ran the installer on a clean machine and found the development stack
publishing Postgres, Redis, MinIO and Mailpit on every interface, behind
the passwords written in its compose file; it publishes them on 127.0.0.1
only now. Last, the other 154 findings were closed before tagging rather
than left for the next release, with the seven gaps the known-open list
named (among them a closed case that still accepted writes, and no
password reset anywhere) and six pieces of security work, DNS-rebinding
protection for collection among them, and a review of that pass found
50 more problems, all fixed before tagging. The entries below run
newest first, from that review back to Wave 1.

The owner took four decisions during the review (docs/00, 61 to 64). A
rejected malware sample is kept, encrypted and under a legal hold, instead
of destroyed, and getting it back takes two people. The role that was
called Case owner is shown as Lead investigator and stays separate from
the Security Officer: the Lead investigator reveals victim PII only under
an authorisation the Security Officer alone grants, the Lead investigator
or the administrator invokes break-glass and the Security Officer alone
reviews it, and no role may hold both halves of either pair. The archived
MinIO build stays pinned, with the risk accepted in writing, and the
readiness register now proves that the object store refuses to delete a
locked object instead of reading the bucket's configuration. Three more
came with the last pass: a password is reset by an administrator, never
by an emailed link; a CLOSED or ARCHIVED case is read-only for its
content while its governance still works; and the API no longer grades a
claim that arrives without one.

Still alpha, still not audited, and still not lawful to operate against
real material until the five blocking items in docs/16 (L1 to L5) are
settled by somebody outside this codebase. Alpha 5.2 stands at Alembic
0059, so an upgrade applies nine revisions, 0060 to 0068, and three of
them change existing data in ways a downgrade does not undo: 0062 revokes
victim-PII authorisations, 0064 rewrites tie confidences, raising ties an
analyst had lowered, without an audit event for any tie it changes, and
0067 sets the review state of the ties entered before it, with an audit
event for each. An existing deployment has steps to take before it
serves again, among them a query to run before migrating; they are the
next subsection.

3448 tests (`def test_` functions); 5051 collected items on
a live stack, 5040 passed and 11 skipped here (the
least-privilege role tests, which need a database initialised with
`NOCTORNAL_APP_DB_PASSWORD`).

### Upgrading from Alpha 5.2

An Alpha 5.2 deployment is the development stack (`infra/docker-compose.yml`,
started by `release/install.sh`, `release/install.ps1` or the launch
scripts), or the same program pointed at your own Postgres, Redis and MinIO
through `.env.local`. Alpha 5.2 stands at Alembic 0059, so this upgrade
applies nine migrations, 0060 to 0068. `infra/production` did not exist in
Alpha 5.2; step 9 is for a stack deployed from it since. Take the steps in
this order. Re-running the installer, or a launch script, performs steps
5 and 6 and starts the API, so run one only once step 4 is done, and never
before step 3, which has to happen before anything migrates. Each step
says what the installer does and how to do it by hand.

**1. Stop the API, and back up.** If you also run a sample origin (a
second process of this code, with `NOCTORNAL_PUBLIC_ORIGIN` set to the
value of `NOCTORNAL_SAMPLE_ORIGIN`), stop it too. Three of the nine
migrations change existing data and a downgrade restores none of them
(0062 revokes authorisations, 0064 rewrites tie confidences, 0067 sets
ties' review state), and 0063's downgrade refuses once any sample is
preserved, so the backup is the way back. The
database, from the repository root:

```sh
docker compose -f infra/docker-compose.yml exec -T postgres pg_dump -U noctornal -Fc -f /tmp/before-alpha6.dump noctornal
docker compose -f infra/docker-compose.yml cp postgres:/tmp/before-alpha6.dump ./noctornal-before-alpha6.dump
```

The dump is written inside the container and copied out, so the same two
lines work in bash and in Windows PowerShell, whose `>` would re-encode a
dump piped through it; `pg_restore` reads the file back. On your own
Postgres, run the same `pg_dump -Fc` against it.

The evidence and raw buckets, with the `mc` that ships inside the MinIO
server image (the credentials are the development compose file's own):

```sh
docker compose -f infra/docker-compose.yml exec -T -e MC_HOST_local=http://noctornal:dev_only_change_me@127.0.0.1:9000 minio mc mirror local/noctornal-evidence /tmp/before-alpha6/evidence
docker compose -f infra/docker-compose.yml exec -T -e MC_HOST_local=http://noctornal:dev_only_change_me@127.0.0.1:9000 minio mc mirror local/noctornal-raw /tmp/before-alpha6/raw
docker compose -f infra/docker-compose.yml cp minio:/tmp/before-alpha6 ./minio-before-alpha6
```

Measured on a throwaway stack running the Alpha 5.2 compose file: both
buckets came out byte for byte. Both copies stay inside their containers
until you remove them (`exec -T postgres rm /tmp/before-alpha6.dump` and
`exec -T minio rm -r /tmp/before-alpha6`, after the same
`docker compose -f infra/docker-compose.yml`). On your own MinIO, mirror
the same two buckets with your own `mc`. The samples bucket is left out on
purpose: it holds live malware, and a copy of it sits where no rejection
reaches, so copy it only if counsel has said to.

Copy `.env.local` with the database, now and every time you back the
database up: a dump restored without it has lost more than its sign-ins.
Its `NOCTORNAL_TOTP_KEK`, and any retired key in
`NOCTORNAL_TOTP_KEK_RETIRED`, seals every column `security/sealed.py`
lists: each enrolled authenticator's secret, each persona's collection
credential, each stored victim credential, the data key of every sample,
preserved samples included once there are any, and an egress profile's
endpoint, a column nothing writes yet. Without the key
that sealed them none of those opens again: no enrolled account can sign
in (login answers 503), and no persona credential, victim credential or
sample can be read again. Nothing recovers them short of the key. Keep
the copy as carefully as the dump, because together they open all of it.

**2. Get the code, and keep `.env.local`.** Update the checkout to
`v0.6.0-alpha`, or unpack the release zip. The zip carries no `.env.local`,
and the installers write a new one, with a new TOTP key and a new ingest
pepper, whenever they find none. A new key opens none of what the old one
sealed (step 1): sign-in answers 503, no persona credential, victim
credential or sample can be read again, and the
`kek_ring_opens_stored_secrets` readiness row goes red. A new pepper
invalidates every issued ingest key, and a credential searched for or
ingested again no longer matches the victim-credential fingerprints
already stored. If you unpack into a new folder, copy `.env.local` into it
before running anything there. The compose file names its project
`noctornal`, so a new folder attaches to the same Docker volumes. The
installers now install the exact versions listed in `constraints.txt` at
the repository root, which the tag and the zip carry, and stop if it is
missing; a virtual environment made under Alpha 5.2 is brought to those
versions the next time an installer runs. By hand, add
`-c constraints.txt` to each `pip install`.

**3. Record the ties migration 0064 will change.** 0064 (step 6) sets
every tie's confidence to the highest grade among its live claims and
writes no audit event for the ties it changes, so the upgraded database
keeps no record of what they held before (step 1's dump does, but only as
a whole database). It also raises a tie an analyst
had lowered with a correction beneath a claim that is still live. Before
anything migrates, and with the API still stopped, save the list from the
repository root:

```sh
docker compose -f infra/docker-compose.yml cp release/alpha6-upgrade/0064-ties-before.sql postgres:/tmp/
docker compose -f infra/docker-compose.yml exec -T postgres psql -U noctornal -d noctornal -f /tmp/0064-ties-before.sql -o /tmp/ties-before-alpha6.txt
docker compose -f infra/docker-compose.yml cp postgres:/tmp/ties-before-alpha6.txt ./ties-before-alpha6.txt
```

Keep the file with the backup. Each row is a tie the upgrade will change:
its case, the value it holds now, the value it will hold, its latest
confidence correction, `analyst_lowered` (an analyst's correction set
today's value and the upgrade will raise it) and `soft_deleted`. The query
reads and changes nothing and runs on the Alpha 5.2 schema; on your own
Postgres, run the same file with `psql`.

**4. Add the new settings to `.env.local`.** The installers leave an
existing `.env.local` untouched, so it lacks the lines a fresh install now
writes:

```sh
INGEST_BUCKET=noctornal-raw
PRESERVE_BUCKET=noctornal-preserved
NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=preserve
NOCTORNAL_MAX_EVIDENCE_BYTES=256MB
NOCTORNAL_MAX_SAMPLE_BYTES=64MB
```

- `INGEST_BUCKET` and `PRESERVE_BUCKET` are the defaults the code already
  uses, written out so they can be seen.
- `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION` is `preserve` when unset.
  `destroy` restores Alpha 5.2's behaviour and belongs only where counsel
  has said rejected material must not be kept (docs/16 L1); a legal hold on
  the sample or its case still refuses a destruction. Any other value
  refuses every rejection that disposes of the bytes until it is corrected.
- The two caps. Alpha 5.2 accepted exhibits and samples up to 256 MiB each.
  Left unset, both stay at 256 MiB and the register's
  `evidence_size_cap_declared` row is red. The lines above keep exhibits at
  256 MiB and lower samples to 64 MiB; declare `NOCTORNAL_MAX_SAMPLE_BYTES=256MiB`
  to keep what you had. The units are binary (`256MB` is 256 MiB). A value
  that is not a size, or is outside 1 MiB to 64 GiB, stops the API from
  starting, and a changed value takes effect only at a restart.

The other settings this release reads are new too, and a development
stack needs none of them:

- `PRESERVE_ENDPOINT`, `PRESERVE_ACCESS_KEY` and `PRESERVE_SECRET_KEY`, the
  preservation store's account. Unset, each falls back to its `SAMPLE_*`
  value and then to `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY` and
  `MINIO_SECRET_KEY`, which suits the development stack, and the register
  says it is using the fallback. If you gave `SAMPLE_ACCESS_KEY` an account
  limited to the samples bucket, every rejection is refused with
  AccessDenied until these three name an account that may write, read and
  set a legal hold in the preservation bucket.
- `PRESERVE_SECURE`, which falls back to `SAMPLE_SECURE` and then to plain
  HTTP, never to `MINIO_SECURE`.
- `NOCTORNAL_TOTP_KEK_ID` (default `env:v1`) and
  `NOCTORNAL_TOTP_KEK_RETIRED` (default empty), the key ring. Leave both
  alone until you rotate the key; the runbook is in `security/envelope.py`.
- `EVIDENCE_LOCK_HORIZON_DAYS` (default 3650), how far ahead one step may
  lock an exhibit in storage. An exhibit is now locked to its case's
  retention date when that is later than the 365 days from lodging, and
  extending the date lengthens every exhibit's lock, never beyond this
  many days from the day it is done. Nobody can shorten a COMPLIANCE
  lock, which is why it has a ceiling.
- `NOCTORNAL_ENV`. Only the exact value `production` means anything: it
  makes the API refuse to start on a development secret, and
  `infra/production` sets it. Leave it unset here.

**5. Create the preservation bucket, with object lock.** Object lock can
only be switched on when a bucket is created.

On the development stack, run `docker compose -f infra/docker-compose.yml
up -d`, which the installers and the launch scripts also run. Its
`minio-init` runs on every `up` and now creates `noctornal-preserved` with
object lock. Measured on a throwaway stack built from the Alpha 5.2 compose
file: after `up -d` with this release's file, the bucket existed with
object lock on, both readiness proofs passed against it, and a held write
made the way a rejection makes it succeeded.

On any other MinIO, create it yourself, with no default retention (a
preserved sample is protected by a per-object legal hold, not a retention
period):

```sh
mc mb --with-lock <alias>/noctornal-preserved
```

If a bucket of that name already exists without object lock, `mc mb
--ignore-existing --with-lock` reports success and changes nothing, and
every rejection into it is refused as a bucket that "would not take a legal
hold". It has to be removed and created again. To check a bucket, `mc stat
--json <alias>/noctornal-preserved` shows `"ObjectLock":{"enabled":"Enabled"}`.
Do not rely on `mc retention info --default`: on a correctly locked bucket
with no default rule it prints "Object locking is not enabled." (measured).

The same `up -d` replaces the MinIO images. Both compose files now pull
`quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z` and
`quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z`, because Docker Hub's
`minio/minio` and `minio/mc` stopped answering anonymous pulls (the MinIO
entry below). A stack that ran `minio/minio:latest` may have been on a
newer server than the pin: on the build machine that tag was
`RELEASE.2025-09-07T16-13-09Z`. The throwaway stack moved from that release
to the pinned one on the same volume, started, and served an object the
newer release had written. That is one small volume and not a proof for
yours, which is one more reason for step 1.

The same `up -d` recreates the other containers from this release's file
too, and keeps their data volumes. Mailpit is pinned to
`axllent/mailpit:v1.31.0` instead of `latest`. It publishes every port on 127.0.0.1
only, so a tool on another machine that reached the stack's Postgres,
Redis, MinIO or Mailpit no longer can, while everything on the host itself
carries on. Until it runs, a stack keeps the old bindings on every
interface, with the passwords written in the compose file. To reach the
MinIO console or Mailpit from another machine, use an SSH tunnel (for
example `ssh -L 9001:127.0.0.1:9001 you@the-host`) rather than changing
the binding back: Docker forwards a published port ahead of the host
firewall, so ufw would not close it. And Redis now refuses writes at its
memory cap instead of evicting the rate limiter's meters, so the
RATE-LIMIT REDIS EVICTS KEYS line no longer appears when the API starts,
and `redis_limiter_store` passes on the bundled stack.

An existing `.env.local` keeps `localhost` in `DATABASE_URL`, `REDIS_URL`,
`MINIO_ENDPOINT` and `SMTP_HOST`, because the installers never rewrite
it, and it still works. A new one names `127.0.0.1`, and on Windows that
matters: with Windows' default address preferences `localhost` resolves
to `::1` first, nothing listens there now, and the refused attempt costs
about two seconds on every new connection to Postgres or MinIO before the
client tries 127.0.0.1. On Windows, change `localhost` to `127.0.0.1` in
those four lines. On Linux nothing needs to change.

**6. Apply the migrations.** From the repository root, with `DATABASE_URL`
set to the schema owner's DSN (the value in `.env.local`):

```sh
.venv/bin/alembic upgrade head        # Windows: .venv\Scripts\alembic upgrade head
```

The installers and the launch scripts run this too. Each revision is its
own transaction, so a refusal keeps every revision before it and nothing
of its own. What each one does to an existing database:

- **0060** grants the least-privilege role `noctornal_app` what it needs,
  and does nothing where that role does not exist, which is every Alpha 5.2
  stack. The role is created only when Postgres initialises a fresh volume
  with `NOCTORNAL_APP_DB_PASSWORD` set (`db/README.md`). A role created
  after this upgrade gets nothing from running `alembic upgrade head`
  again, because Alembic never re-runs a revision it has recorded; run
  `release/alpha6-upgrade/app-role-grants.sql` with `psql` as the schema
  owner instead, which applies 0060's grants and 0063's revoke.
- **0061** adds `lab.download_ticket`, the one-shot ticket a Lab download
  now crosses to the sample origin on.
- **0062** shows `CASE_OWNER` as Lead investigator. The key is unchanged,
  so no permission check, case assignment or script that reads it moves.
  It takes `victim_pii.authorise` from that role and gives it
  `victim_pii.reveal`, which no role held before, so the reveal that
  refused everyone under Alpha 5.2 now opens for a Lead investigator under
  a live authorisation and a step-up, and authorising is the Security
  Officer's alone. It adds `iam.separated_duty`, whose trigger refuses any
  grant that would give one role both halves of a two-person control.
  Then it **revokes** every live victim-PII authorisation whose grantor
  holds no current assignment on that case under a role that may
  authorise: every one a Lead investigator granted a co-lead, and any
  granted by an officer who has since left the case or whose assignment
  has expired. Each revocation writes a `PII_AUTHORISATION_REVOKED` audit
  event (actor SYSTEM) naming both people and the reason. The grantee's
  next reveal answers 451, and the Security Officer grants a new
  authorisation if one is still wanted. Those granted by a Security
  Officer still assigned to the case stand, and expired ones are left
  alone. A downgrade puts the old grants back and leaves the revocations
  in place. It refuses, by name, a database where some role would hold
  both halves of a pair, which happens only where role grants were edited
  by hand: revoke one half and run it again.
- **0063** adds the columns and the authorisation table for preserved
  samples, and two step-up permissions: `sample.preserved.authorise`
  (Security Officer) and `sample.preserved.retrieve` (Lead investigator).
  Its downgrade refuses while any sample is preserved.
- **0064** makes a tie's confidence the highest grade among its live claims
  about the tie (LOW when none grades it), holds it there with triggers,
  and backfills every edge whose stored value disagreed, writing no audit
  event for any of them (step 3 kept the record). Under Alpha 5.2 the API
  stored every new tie as LOW whatever the analyst chose, so expect ties
  to move to the grade their claims carry. A tie an analyst lowered with a
  correction beneath a claim that is still live goes back up to that
  claim's grade; the correction, the value it stated and its
  `EDGE_UPDATED` audit row are kept. A direct `UPDATE` of
  `core.edge.confidence` is refused from here on. A downgrade drops the
  triggers and does not restore the old values. A demo estate seeded
  before this revision gets the seed's grades back with
  `scripts/seed_showcase.py --owner-email you@example.com --regrade`.
- **0065** adds two trigram indexes, on `core.selector.raw_value` and
  `core.evidence.title`, for fragment search.
- **0066** adds `iam.app_user.must_change_password`, false for every
  existing account, so everyone signs in as before. An administrator's
  password reset sets it (step 8).
- **0067** gives the ties entered before this release the review state
  this release gives a tie when it is made. Under Alpha 5.2 nothing set a
  tie's review state, so every tie read PROPOSED and every node wore the
  unreviewed-proposal ring. A live tie whose founding claim is a
  person's, or which a reviewer accepted from Triage, becomes ACCEPTED,
  with an `EDGE_REVIEWED` audit event each (actor SYSTEM, "by the Alpha 6
  upgrade"), which the tie inspector's Review history shows. A tie
  founded on a machine's claim that nobody accepted stays PROPOSED. A
  downgrade leaves the states and the events as they are.
- **0068** lets a one-shot download ticket name an exhibit as well as a
  sample, which is how an exhibit of attacker markup (a captured email,
  page or HAR) is now produced through the sample origin (step 8). It
  changes no existing row, and its downgrade deletes the exhibit tickets,
  which are one-shot and short-lived.

Then list the lowered ties for the analysts:

```sh
docker compose -f infra/docker-compose.yml cp release/alpha6-upgrade/0064-ties-after.sql postgres:/tmp/
docker compose -f infra/docker-compose.yml exec -T postgres psql -U noctornal -d noctornal -f /tmp/0064-ties-after.sql -o /tmp/ties-lowered-alpha6.txt
docker compose -f infra/docker-compose.yml cp postgres:/tmp/ties-lowered-alpha6.txt ./ties-lowered-alpha6.txt
```

Each row is a tie whose latest live confidence correction states a lower
grade than the tie now holds, with who made the correction and when. A
tie the analyst lowered and later put back is not listed. A tie
corroborated at a higher grade after the correction is, and its rise may
be deserved, so each row wants an analyst's judgement rather than a redo.
To lower a tie again: add a claim at the lower grade (the tie inspector
has the control), then retract the claim that grades it higher.

**If a downgrade is refused.** A downgrade below 0063 on a database that
holds a preserved sample undoes 0068 to 0064, commits each, and stops at
0063 with 0063's refusal. No release runs on that state: the tie rule and
its triggers are gone, so a confidence correction that would change a
tie's grade fails with a 400, and a claim added or retracted no longer
moves its tie. Run `alembic upgrade head` to return to 0068, which derives
every tie again. Going back to Alpha 5.2 once a sample is preserved means
restoring step 1's backup, and each preserved copy then stays in
`noctornal-preserved` under its hold, named by no row, where nothing in
the product can delete it.

**7. Start the API and read the readiness register** (Administration in the
console, or `GET /api/v1/admin/readiness` as a system administrator,
signed in within the last 15 minutes: an older session gets 403
"re-authentication required", and signing in again cures it). A
sample origin starts on the new code too, with the same settings as the
API, step 4's included: a Lab download now reaches it on a one-shot ticket
(0061) that only the new code redeems, and it is the process that reads a
preserved sample back out of the preservation store. Rows that are new or
stricter, and may be red on an upgraded stack:

- `preservation_bucket_object_lock`, new. Red with `NoSuchBucket` until
  step 5 is done, and red when the bucket is not locked or the account
  cannot set a hold. A rejection into a missing or unlocked bucket is
  refused, and the sample stays where it was.
- `evidence_size_cap_declared`, new. Red until
  `NOCTORNAL_MAX_EVIDENCE_BYTES` is declared, and again whenever it is
  edited without a restart.
- `app_db_role_not_owner`, new. Red wherever the API connects as the schema
  owner or a superuser, which is every Alpha 5.2 stack (the development
  compose's `noctornal` is both). Expected there, and not blocking.
- `kek_ring_opens_stored_secrets`, new. Red when a stored secret was sealed
  by a key that is not in the ring; a replaced `.env.local` (step 2) is one
  way to get there. The rotation runbook is in `security/envelope.py` and
  `infra/production/README.md`.
- `ingest_pepper_set`, new. Red only if `NOCTORNAL_INGEST_PEPPER` is unset;
  both Alpha 5.2 installers wrote it.
- `credentials_not_published`, new and not blocking. Red while any
  credential in the process's environment is a value published in this
  repository or a vendor default, naming the variables and never the
  values. That is every development stack, whose compose passwords are in
  the source, and it is expected there. A process with
  `NOCTORNAL_ENV=production` refuses to start on the same values.
- `redis_limiter_isolated`, new and not blocking. Red when the rate
  limiter's Redis also holds keys the limiter did not write, in its own
  database or another one. It reads counts, never a key or a value.
- `evidence_bucket_object_lock`, stricter. It passed on the bucket reporting
  a lock configuration. It now writes a canary, `.noctornal-worm-canary`,
  under a one-day COMPLIANCE retention, and passes only when the store
  refuses to delete that version and records COMPLIANCE on it, so a store
  that accepts a lock and deletes anyway, or records GOVERNANCE, now fails.
  `preservation_bucket_object_lock` makes the same proof in the
  preservation bucket, and a second one with `.noctornal-hold-canary` under
  a legal hold. Those objects are the register's: a COMPLIANCE canary
  cannot be deleted until its day is up (later probes remove the old
  ones), and the hold canary is kept for good.
- **The blocking tier**, new. While any of `prohibited_content_policy`,
  `sample_origin_configured`, `retention_rules_confirmed` or
  `security_officer_present` is red, `POST
  /api/v1/collection/sources/{id}/run` answers 409 naming them and
  `scripts/collection_poll.py` refuses its whole pass. A stack that polled
  sources under Alpha 5.2 stops polling until all four pass. The
  development stack sets neither the policy nor the sample origin, the six
  seeded retention rules are placeholders until somebody confirms each
  one, and `security_officer_present` stays red until an active account
  holds `SECURITY_OFFICER`, which no account the installer made does
  (step 8).

**8. Tell the people who use it.**

- Rejecting a sample now preserves it (step 4), and the Lab's confirmation
  names the sample and says what will happen to its bytes. Getting a
  preserved sample back takes a Security Officer's authorisation naming one
  Lead investigator for one sample, for at most thirty days, and then that
  Lead investigator, who receives the same encrypted archive a download
  returns, through the sample origin, so a retrieval needs
  `NOCTORNAL_SAMPLE_ORIGIN` just as a download does. Nothing in the product
  deletes a preserved copy or lifts its hold; that is an operator's act, on
  counsel's instruction. Samples rejected under Alpha 5.2 were destroyed,
  and stay so.
- Case owner reads Lead investigator on screen, and a Lead investigator can
  reveal victim PII under a live authorisation from the Security Officer.
- Ties may read a different confidence than they did (0064), and the list
  from step 6 names the ones an analyst had lowered. Ties now carry a
  review state a reviewer can set from the tie inspector, and the
  unreviewed ring stays only on ties founded on a machine's claim (0067).
- A CLOSED or ARCHIVED case is read-only: its content can be read but not
  changed, and its governance (reopening, holds, retention, sharing,
  break-glass, purge) still works. Reopen a closed case to work on it.
- A forgotten password is reset by an administrator from the account's
  card in Administration, which shows a one-time password once. Its first
  sign-in asks for a new password and a fresh authenticator code. The last
  administrator is reset from the server's shell with
  `scripts/bootstrap.py reset-password --email ...`. Everyone can change
  their own password under Account.
- Rejecting a sample now asks for a fresh sign-in first.
- An account an administrator creates must choose its own password at its
  first sign-in, and so must one made with `scripts/bootstrap.py
  create-user` while any other account exists (the installers' advice for
  a Security Officer). The first account on an empty database keeps the
  password it was given.
- A capture is stored no lower than its case's classification, and a
  capture into a compartmented case is refused until collected documents
  can carry compartments.
- An exhibit of attacker markup (a captured email, page or HAR) is
  produced from its card through the sample origin (0068), so producing
  one needs `NOCTORNAL_SAMPLE_ORIGIN` just as a sample download does.
- Saving a later retention date on a case asks first, because it
  lengthens every exhibit's storage lock (step 4). An exhibit lodged
  before this release is locked for its original 365 days; the Evidence
  pane says which ones end before their case's date and can lengthen
  them.
- Every analysis run stored before this release reads as not current
  once, until it is run again: a run is now also keyed on the entities'
  names and types.
- Each two-person control needs two people. Nobody may authorise their
  own victim-PII reveal or preserved-sample retrieval, and break-glass is
  now refused when nobody but the invoker holds `SECURITY_OFFICER` (under
  Alpha 5.2 a sole officer could invoke it). What a one-person install has
  depends on how its first account was made. The console's first run gives
  it four roles, Security Officer among them, so that operator cannot
  invoke break-glass. `release/install.sh` and
  `scripts/bootstrap.py create-user` (the command the launch scripts print
  when no account exists) give it Lead investigator and system
  administrator only, so that install has no Security Officer at all:
  break-glass is refused as it was under Alpha 5.2, nobody can grant a
  victim-PII authorisation (under Alpha 5.2 a case owner could) or a
  preserved-sample retrieval, and `security_officer_present` stays red and
  blocks collection (step 7). The installers now say so when they finish
  and print the command that makes a second person the officer. Either
  way, give `SECURITY_OFFICER` to a second person, with that command or
  with Grant role in Administration.
- Script clients. `POST /api/v1/auth/login` answers 204 with the cookie
  pair and no body: use the `__Host-session` cookie's value as a Bearer
  token, or send the cookie with an `x-csrf-token` header matching
  `__Host-csrf` on unsafe methods, or mint a session with
  `scripts/bootstrap.py session`, which the audit trail records as an
  MFA-bypassed login. `POST /api/v1/samples/{id}/reject` with
  `purge_bytes: true`, the default, now disposes of the bytes as
  `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION` says, which is to preserve them
  unless the deployment chose `destroy`; the API document says so, and
  `GET /api/v1/samples/policy` reports the disposition in force.
  `POST /api/v1/cases/{id}/edges`
  refuses a top-level `confidence` (send `assertion.confidence`), and a
  correction that would lower a tie beneath a live claim answers 409.
  `POST /api/v1/cases/{id}/report` with `fmt=markdown` answers 409: the file
  now comes from `POST /api/v1/cases/{id}/report/release` with destination
  `export`. A bare positive Telegram id is refused as a selector;
  `python scripts/telegram_bare_ids.py` lists the rows recorded under the
  old assumption for an analyst to confirm, and changes nothing.
  Every body that records a claim (`POST` and `PATCH` of nodes and edges,
  and adding an assertion) must now carry the claim's `basis`,
  `reliability`, `credibility` and `confidence`; a missing one answers 422
  naming it, where Alpha 5.2 recorded a direct observation graded F6 and
  LOW. Any write to a CLOSED or ARCHIVED case's content answers 409 "Case
  is read-only". A login for an account whose password an administrator
  reset answers 403 with the problem type
  `urn:noctornal:problem:password-change-required` and no session; repeat
  it with `new_password` and a fresh code. `POST
  /api/v1/samples/{id}/reject` needs a session that signed in within the
  last 15 minutes. Accepting a proposal the caller was never shown answers
  404, as rejecting and deferring one already did, and accepting a claim
  onto an entity labelled below the material it came from answers 409.
  Lab writes on a sample whose case is CLOSED or ARCHIVED answer 409. A
  dead letter reached through a case replays only into that case or into
  quarantine. `scripts/collection_poll.py` stops starting polls after
  `--max-seconds` (a source it did not reach is counted in a new
  `deferred=` field), and each fetch has its own wall-clock allowance.

**9. A stack deployed from `infra/production` on main before this
release.** The development stack cannot be turned into one in place: the
least-privilege role exists only on a volume initialised with
`NOCTORNAL_APP_DB_PASSWORD`, and this release has no tool that moves a
stack's data. Back one up first as the Backups paragraph of
`infra/production/README.md` now says: the database, the evidence and raw
buckets, and `secrets.env`. After `git pull`, and before the update below,
which migrates, record step 3's list through that stack's Postgres:

```sh
docker compose -p noctornal-prod -f infra/production/compose.yml exec -T postgres \
  sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U noctornal -d noctornal' \
  < release/alpha6-upgrade/0064-ties-before.sql > ties-before-alpha6.txt
```

and after the update, the same with `0064-ties-after.sql`. On a stack
whose database is already at 0064 or later, the first query returns
nothing, because there is nothing left for 0064 to change. Then add to
`secrets.env` what `secrets.env.example` now carries: `PRESERVE_BUCKET`,
`PRESERVE_ACCESS_KEY` and `PRESERVE_SECRET_KEY` (you choose them, and
`minio-init` mints them as an account that can write, read and set a hold
in that bucket and cannot delete or lift one),
`NOCTORNAL_REJECTED_SAMPLE_DISPOSITION`, and
`NOCTORNAL_MAX_EVIDENCE_BYTES` if yours predates it, because a production
boot refuses without it. Then the README's update:

```sh
docker compose -p noctornal-prod -f infra/production/compose.yml up -d --build
```

`minio-init` creates the locked bucket and the account, and `migrate`
applies the revisions the database lacks before the API starts. Without
the two keys the preservation store falls back to the `SAMPLE_*` account,
which cannot reach the bucket, so every rejection that disposes of the
bytes is refused. A production API now also refuses to start while any
password or secret in `secrets.env` is a value published in this
repository or MinIO's default (step 7, `credentials_not_published`), and
names each variable it refuses; replace those before the update.

### A review of the last pass, before tagging

The pass below was reviewed as a whole against a running copy of the demo
estate before anything was tagged. It found 50 problems, each shown to be
real before it was fixed: 24 were traced end to end when they were
reported, and the 26 smaller ones were proved by whoever fixed them. All
50 are fixed. The finding the pass had left half done, producing an exhibit
of attacker markup, is finished too.

**Security.**
- Accepting a claim from a contact block wrote its identifier onto the
  entity it named, at that entity's labels. A block classified RED under
  a compartment, attached to a CLEAR persona, put the RED identifier and
  the forum address it came from in front of every reader of the case,
  including the readers the Triage queue had hidden the proposal from,
  while the card showed a TLP:RED chip. The accept is now refused (409)
  unless the entity already carries the block's classification and
  compartments, the card says why and offers no Accept, and the service
  checks the same rule for every caller, not only the route.
- A capture was stored at the level picked on the form, AMBER by default,
  whatever the case was, and a document is case-less: a RED case's
  capture could be listed among AMBER readers' collected documents. A
  capture is now stored no lower than its case, the form starts at the
  case's level and offers nothing below it, and a capture into a
  compartmented case is refused, because a collected document cannot yet
  carry compartments. Text captured before keeps the label it was first
  stored at, and a reply never names a label above the reader.
- The deception pane's Propose looked for an existing proposal without
  the reader's labels, so it both revealed and silently swallowed
  proposals above them. It now reads the queue the way Triage does.
- Dead-letter replay under break-glass counted no use of the grant, made
  a record at the fragment's own labels without checking the target case
  was cleared for them, and could put a fragment into a case its batch
  never fed, which then showed that batch's other dead letters to the new
  case's readers. Each replay is now counted and gated at the fragment's
  labels, and a fragment goes back only to its own case or to
  quarantine. Exhibit export and category correction each counted two
  uses of a grant per request and now count one; a case-wide rescore
  reached only through a grant now counts its one.
- `collection.fetch` had a timeout per socket operation and none
  overall, so a watched source that answered one byte at a time could
  hold the collector pass and the notification drain for as long as it
  liked. Each fetch now has a wall-clock allowance covering every hop,
  connection, handshake, header and body, and `collection_poll.py` a
  budget for the whole pass (`--max-seconds`); a source it runs out of
  time for is counted as deferred.
- The Lab accepted assignment, analysis, proposals, detonation requests
  and rejection on a sample whose case was CLOSED or ARCHIVED. They are
  refused like every other content write, and the card says so.
- An account an administrator created kept the password the
  administrator had seen. It must be replaced at its first sign-in, as a
  reset one already was, and so must one made with `bootstrap.py
  create-user` while any other account exists. A refused must-change
  sign-in no longer spends a single-use recovery code or reads as the
  account's last sign-in.
- The tab title carried the case code and its TLP marking, and the
  browser keeps titles in its history after sign-out. It reads "Case"
  now.
- The ingest key secret stayed on screen through pane changes and case
  switches. It is cleared as the Administration one-time credentials are.

**Exhibits of attacker markup can be produced.** A captured email, page
or HAR is never served from the console's origin, and until now that
meant it could not be produced at all. Export on such an exhibit now
mints a one-shot ticket (the same permission and fresh sign-in as any
export; migration 0068 lets a ticket name an exhibit), and the file is
fetched from the separate sample origin as an encrypted archive, with an
EXPORTED custody row.

**An exhibit's lock follows its case.** An exhibit was locked in storage
for 365 days from lodging whatever its case's retention. It is now
locked to the case's retention date when that is later, and extending
the date lengthens every exhibit's lock, both capped at ten years ahead
in one step (`EVIDENCE_LOCK_HORIZON_DAYS`). Nobody can shorten a lock,
so the case record asks before saving a later date, with the date
spelled out. An exhibit locked for less time than its case is retained
says so, and the Evidence pane can lengthen those locks. The count it
reports covers only exhibits the reader may see.

**Analysis, ACH and first seen.**
- The Analysis pane counted a DISPUTED tie as reviewed, and told the
  analyst every tie behind the brokers and the removal set had been
  reviewed when some were disputed.
- A renamed entity kept its old name in cached results, and the run
  still read as current. Stored runs are keyed on labels and types too
  now, so every run stored before this release reads as not current
  once, until it is run again.
- Moving the as-of time while a run was computing put the old instant's
  results under the new graph. The trend chart left out the run just
  made.
- ACH hid every stance once no hypothesis was left live, and said
  nothing had been scored; its assertion picker survived a case switch
  and offered the last case's claim; and the pane now says when cells
  above the reader were left out.
- An entity's first and last seen dropped every sighting of a persona
  merged into it, and an entity accepted from Triage had none, although
  its capture is dated.

**Smaller.** A sign-in more than 15 minutes old, on any case action that
needs a fresh one, is asked to sign in again; it used to be told it
lacked a permission it holds, which only report export had been taught
not to say. Canvas names are placed clear of the on-canvas controls,
which had cut handles into other plausible handles. The Evidence register
refreshes after an exhibit is linked, claimed or retracted. The coverage
chip counts what a focus draws. Triage acts on the proposal the analyst
picked even after a live reload, and every A, R or D dialog names it; a
Reviewer is not offered an Undo their role cannot perform; a closed
case's proposals no longer count as waiting. The Case record and Status
dialogs are modal. The tag picker no longer sends its prompt as a tag.
The Share dialog's end time is UTC, as every other time is. A malformed
certificate hash is a 422 instead of a 500, and a vishing call no longer
proposes the victim's own SIP host as attacker infrastructure. A
`REDIS_URL` carrying its password as a query argument is accepted, and
redacted in logs. An ElastiCache limiter is no longer reported as
shared. The launchers print install commands that use
`constraints.txt`. The demo seeders and tests use `.example` hosts.

The README screenshots were taken again on this console, and taking them
found two more. On a tall window, Trend in the Analysis pane scrolled the
whole workspace up under the header, where nothing the analyst could do
scrolled it back; the workspace can no longer be scrolled by a script at
all. And the trend printed its lowest value in the top right corner,
which on a rising line is where the newest and highest point sits; both
ends now share one label on the left.

### The rest of the review, the seven gaps, and security work

The 154 findings of the 2026-09-22 review that the sections below left
open are closed before this release instead of after it: 148 are fixed,
5 turned out to be fixed already on the release candidate, and one was
fixed in part here and finished in the section above. Each
fix was checked by someone other than its author before it was merged,
and the merged result was reviewed again as a whole. The seven gaps the
known-open list named are closed too, and six pieces of security work
were done that no finding asked for.

**A CLOSED or ARCHIVED case is read-only.** The server accepted writes to
a closed case. Now every route that writes case content (the graph,
claims, corrections, tie review, evidence and its links, captures,
proposals, comms, analysis, tags, samples) answers 409 "Case is
read-only" on a CLOSED, ARCHIVED or PURGED case and writes a
`CASE_READ_ONLY_REFUSED` audit event. The check sits in
`authorize_object`, which every one of those routes already calls, so a
route added later inherits it. Governance still works on a closed case:
reopening it, legal holds, retention, sharing, break-glass and purge.
The console turns the write controls off on such a case, including the
ones a pane draws after it opens, and says what the server refuses.

**Password reset, issued by an administrator.** There was no way to reset
a password. An administrator now resets a colleague's password from the
account card in Administration (`POST /api/v1/admin/users/{id}/password`,
`user.manage` with a fresh sign-in). The reset issues a one-time
password, shown once, signs out every session the account had, and clears
any lockout. The next sign-in with it opens no session: it asks for a new
password, and only then signs in (migration 0066 adds the flag that
enforces this). Anyone can change their own password under Account
(`POST /api/v1/auth/password`, the current password required). The last
administrator, whom nobody can reset from the console, is reset with
`scripts/bootstrap.py reset-password --email ...`, which calls the same
service. There is no emailed link, by decision: a reset goes through a
person who knows the colleague.

**The API no longer grades a claim for you.** A request that left the
grade out was recorded as a direct observation graded F6 and LOW, which
no analyst chose. Basis, reliability, credibility and confidence are now
required on every body that records a claim, and a missing one is a 422
naming it. The console's Correct... is a graded form for the same
reason. Corrections recorded before this release keep the old defaults,
and the console still labels them as corrections rather than by that
basis.

**First seen is derived.** Nothing ever wrote an entity's first-seen
date, so the column was always blank. First and last seen now come from
the observation dates of the entity's live claims, read where they are
shown, with no migration and nothing new to keep in step.

**A tie can be reviewed.** Every tie read review PROPOSED forever,
including ties an analyst entered and proposals a reviewer had accepted,
so every node wore the unreviewed ring and the inspector's "Unreviewed
proposals" equalled its tie count. A tie a person enters is now ACCEPTED
when it is made, one founded on a machine's claim is PROPOSED, and the
tie inspector has a Review section (`proposal.review`, an
`EDGE_REVIEWED` audit event, and the tie's review history). Migration
0067 gives the ties entered before this release the state they would
have had, with an `EDGE_REVIEWED` event each, "by the Alpha 6 upgrade".

**A capture's classification reaches its proposals.** A proposal raised
from a RED capture was accepted at AMBER unless the reviewer changed it.
The capture's level is now written into each proposal, shown on the
Triage card, and is the default and the floor of the accept: the
strictest of the proposal, its source and the case. A reader who was
never shown a proposal gets a 404 on accepting it, as on reject and
defer, instead of a refusal that named the proposal's label.

**Rejecting a sample needs a fresh sign-in,** since a rejection moves the
bytes into a store they leave only with two people.

**Security work.**
- `collection.fetch` checked where a name resolved and then let the
  socket layer resolve it again, so a resolver that answered a public
  address to the check and a private one to the connect got through (DNS
  rebinding). Each hop is now resolved once, every answer is checked, and
  the socket connects to the checked addresses by number, with the Host
  header, SNI and certificate check still on the name. Redirects are
  followed hop by hop under the same rule, a URL carrying a user name and
  password is refused, and a TLS context that does not verify is refused.
  A policy-enforcing egress proxy for persona traffic is still not built.
- A production process refuses to start when any service credential is a
  value published in this repository or a vendor default (the
  development compose passwords, MinIO's own default), naming the
  variable and never the value. The readiness register reports the same
  on every process as `credentials_not_published`. User names and access
  keys are not refused; replace them anyway.
- `redis_limiter_isolated`, a new readiness row, reports when the rate
  limiter's Redis also holds other keys, which an eviction policy or a
  flush aimed at them would take with it. It reads counts only, never a
  key or a value.
- The dependencies are pinned. `constraints.txt` fixes all 47
  distributions the API installs, each checked for wheels on Linux,
  Windows and macOS for Python 3.12 to 3.14, and the installers, CI and
  the production image all install through it. Mailpit is pinned to a
  release instead of `latest`.
- On a case above the invoker's clearance, one request under break-glass
  could record two uses of the grant, so a grant ran out at half its
  allowance and its review read double. Each request now records one.
- A registered compartment can be renamed or retired from Administration
  (`POST /api/v1/compartments/{key}/rename` and `/retire`, with a fresh
  sign-in). A retirement is refused while anything still carries the
  key, and the refusal counts what does and names only what the
  administrator can already open.

**The rest, by pane.** The highs among the 154:
- Triage. Ctrl+A, Ctrl+D and Ctrl+R accepted, deferred and rejected the
  focused proposal, and the single letters fired from anywhere on the
  pane. Letters now work only in the list, A asks first, an accept can be
  undone, and browser chords are left to the browser. Cards say what a
  proposal attaches to what, carry their TLP mark, and open the document
  they came from. The graph's "unreviewed proposals" ring now counts what
  Triage lists.
- Approvals and notifications. "Open approvals" opened the current case's
  approvals, not the request's. A merge approval showed two UUIDs and no
  requester; it names both entities, which one leaves the graph, and who
  asked, and offers only the buttons the server allows that person.
- Analysis. Results stayed on screen as current after the graph or the
  as-of time moved; they are now marked stale or cleared. The trend
  plotted when someone pressed Run instead of the world time measured,
  and cut off its newest runs on first use. "Brokers worth a look" called
  ordinary high-degree actors structural-hole spanners.
- Competing hypotheses. A row never scored against one hypothesis was
  called undiagnostic; a stance's note was never shown and was erased on
  every rescore; "refute this first" never appeared; a hypothesis could
  not be accepted, rejected, edited or removed from the console; and
  Cancel on "Why withdraw it?" withdrew the assumption anyway.
- Feeds. Dead letters did not say which feed failed, showed one global
  list in every case, and could not be replayed; a watched-selector hit
  named no selector; queue and quarantine records could not be opened,
  linked, discarded or attached.
- The graph. Ordinary navigation spent the analytics budget until Node
  size switched off and the evidence headline disappeared; metrics now
  have their own allowance and are cached. At 200% zoom the timeline,
  legend and most projection controls could not be reached.
- Evidence. The upload form could not record when, where or under what
  authority an exhibit was obtained.
- The Lab. A malware analyst could not assign a sample or record findings
  from the console.
- Administration. Compartment read-ins could be neither seen nor set, so
  nobody could be given access to a compartmented case from the console.

The mediums and lows are in the same panes: custody rows a court can
read (names, UTC to the second, the lock's end), the exhibit register
paged instead of capped at 200, search across collected documents and
claims, quiet hours applied in the zone they are labelled with, loading
states that stop claiming "Every source is healthy." before anything has
loaded, error banners below the app bar that expire, the case record
shown and correctable, the open case and pane kept in the address so a
reload or Back returns to it, and contrast raised to AA on every raised
sheet.

- Left open by this pass. An exhibit of attacker markup (a captured
  `.eml`, page or HAR) could not be produced, because it may leave only
  through the separate sample origin, and exhibit locks were not extended
  when a case's retention was; the section above finishes both. Still to
  do: the Analysis pane has no reviewed-ties-only projection, and the
  cron scripts and the migration job do not refuse a published credential
  the way the API does.

### What the release checks found

Before this release was tagged, the installer was run on a clean Ubuntu
24.04 machine, then run again on the fixed tree, and the documents were
read against the code. `release/CLEAN-VM-INSTALL.md` records both runs,
in sections 9 and 10.

**The development stack no longer puts its services on the network.**
`infra/docker-compose.yml` published Postgres, Redis, MinIO and its
console, and Mailpit on every interface, with the passwords written in
that file, and every release before this one did the same. On a Linux
host, anyone who could reach the machine could log in to Postgres as a
superuser and to MinIO as root. A host firewall did not help: Docker
forwards a published port through its own NAT rules before ufw sees the
packet, and on the clean machine Redis and Postgres still answered with
ufw denying all incoming traffic. Every port is now bound to 127.0.0.1,
`test_compose_exposure.py` refuses any other binding, and `SECURITY.md`,
which said the file published its ports to localhost, says 127.0.0.1. A
stack started from an earlier release keeps its old bindings until
`docker compose -f infra/docker-compose.yml up -d` recreates its
containers, which keeps the data volumes; the upgrade notes above include
that step.

**Redis no longer evicts the rate limiter's meters.** The development
Redis ran `allkeys-lru`, so under memory pressure it could delete a live
meter, and a deleted meter admits the subject it was refusing with a full
burst. Every start of the API printed RATE-LIMIT REDIS EVICTS KEYS, and
the readiness register's `redis_limiter_store` failed on a fresh
install, over a setting the bundled stack had chosen. It runs
`noeviction` now, as the production file already did: at its 1 GB cap it
refuses writes, and each limit falls back to its declared
`on_backend_failure`.

**minio-init's log no longer opens with an error.** It waited for MinIO by
running `mc alias set` until it worked, and the attempts made before MinIO
listened logged "mc: <ERROR> Unable to initialize new alias ... connection
refused" on every clean start, which is the line anyone reading the log
after an unrelated failure would take for its cause. The wait is quiet
now, and bounded: if MinIO has not accepted the credentials after about
two minutes, it shows the real error once and exits 1.

**Mailpit answers SMTP at once.** It looked up the reverse DNS of every
client before greeting it, and on the development machine the greeting
took between 1 and 10 seconds, against a send timeout of 10.
`--smtp-disable-rdns` turns the lookup off; on the clean machine the
greeting took 4 ms.

**The installers and `release/INSTALL.md`.**
- Both Windows recovery commands in `INSTALL.md`, the `create-user` one
  and the TOTP-bypass session one, had a BACKSPACE byte where
  `scripts\bootstrap.py` belonged, so each printed as `scriptsootstrap.py`
  and failed when copied. Every tagged release from Alpha 1 to Alpha 5.2
  shipped them that way.
- The first command printed after the account was made was
  `python scripts/bootstrap.py demo-case`, which exits 127 on a stock
  Ubuntu (it has no `python`) and names the wrong seeder. `install.sh`,
  `launch.ps1` and `bootstrap.py create-user` now print the console
  address and the README's First run command with the project's
  interpreter, `.venv/bin/python` or `.venv\Scripts\python`, and
  `bootstrap.py`'s import hint names `.venv` instead of a `pip install`
  that PEP 668 refuses.
- The Debian and Ubuntu advice is
  `sudo apt update && sudo apt install python3.12-venv`: on a fresh cloud
  image the package lists are empty, and the install alone answers "has
  no installation candidate".
- Nobody holds the Security Officer role on a fresh install, so the
  blocking `security_officer_present` check fails, collection runs and
  break-glass are refused, and nobody can read the audit trail.
  `install.sh` and `launch.ps1` count the officers and, when there are
  none, say so and print the command that makes a second person one.
  The command's example address is `security.officer@example.org`, which
  the showcase seeder does not use. `INSTALL.md` says the same, and that the readiness
  register wants a sign-in from the last 15 minutes.
- The banners and `INSTALL.md` said four legal decisions and pointed at a
  README section that does not exist. They say five, L1 to L5, and name
  the heading in the README at the project root. `release/README.md`,
  `release/MANUAL.md` and `ARCHITECTURE.md` say five too, and
  `release/MANUAL.md` no longer says that a rejection destroys the sample.
- A new `.env.local` names every service `127.0.0.1` rather than
  `localhost`. Nothing listens on `::1` once the ports are bound to
  127.0.0.1, and Windows tries `::1` first
  for `localhost` and waits about two seconds for the refusal. An existing
  `.env.local` is never rewritten; the upgrade notes above say what to
  change in it.
- `install.sh` checks the API port before starting it and stops with the
  message `INSTALL.md` quotes. `--help` in both shell scripts stops at the
  end of the header. Both launchers name the ports the compose file
  publishes. `alembic` with no `DATABASE_URL` refuses in one line that
  names `.env.local`, where it ended in a traceback. The README and
  `INSTALL.md` share one prerequisites table, from the clean machine's
  measurements. `INSTALL.md`'s test recipe makes a scratch database,
  because some tests migrate the database they are given down and back
  up.
- The warning printed when `.env.local` is written spoke of
  authenticators alone. The installers and launchers now say that the key
  in it seals persona and victim credentials and every stored sample's
  key as well, and that none of them can be decrypted without it.
- What the installers, the launchers and `scripts/*.py` print, `--help`
  text included, carries no em dash, en dash or spaced double hyphen, as
  the server's copy already did, and the installers and launchers agree
  their plurals with their counts.

Tests hold each of these against the scripts and the code.

**Control bytes are refused in every tracked text file.**
`scripts/check_source_hygiene.py` looked for NUL and not for the
BACKSPACE that broke those two commands, and it read a fixed list of
suffixes that left out `start.cmd`, the Dockerfile, the Caddyfile and
other tracked text. It now refuses every control byte except tab, line
feed and carriage return, in every text file the repository tracks.
`test_source_hygiene.py` proves the check on bytes built for it, and
compares the files it reads with the files git calls text.

**Upgrading from Alpha 5.2 has written steps.** The upgrade notes above
take an existing deployment through it in order, and
`release/alpha6-upgrade/` holds the SQL they use.
`0064-ties-before.sql`, run before migrating, lists every tie migration
0064 will change and the value each holds now, because the upgraded
database keeps no record of them. `0064-ties-after.sql` lists the ties an
analyst had lowered, for a second look. `app-role-grants.sql` grants a
least-privilege role created after the upgrade what 0060 and 0063 would
have, because Alembic never re-runs a revision it has recorded.
`test_alpha6_upgrade_contract.py` holds the grants file to the
migrations, and `test_alpha6_upgrade_ties_pg.py` runs both tie queries
against a database shaped the way Alpha 5.2 leaves one and holds them to
what 0064 does. The production README's backups paragraph now gives the
command that copies the evidence and raw buckets, through the
`minio-init` service since MinIO publishes no port there, where it had
two commented `mc mirror` lines and no alias to run them with. It also
says that `secrets.env` goes with every backup, because the TOTP key in
it seals persona credentials, victim credentials and every sample's data
key as well as the second factors.

For script clients, `POST /samples/{id}/reject` no longer documents
itself as destroying the bytes, and its `purge_bytes` field says what
each value does, so the API document shows the change of default.

**Two smaller ones.** The production compose file tags the image it
builds, and nothing held that tag to the version, so this release would
have gone on building `noctornal-api:0.5.2`; `test_version_contract.py`
now requires the two to be equal. And `scripts/refresh_counters.py`, which
regenerates the counters the documents quote, crashed on Python 3.12, the
documented minimum, because `Path.read_text` takes `newline` only from
3.13. It reads bytes and decodes them now.

### New README screenshots, and what taking them found

All 16 screenshots in the README are new, taken from the restyled console
on the TLP:CLEAR showcase case, each against the README paragraph it
illustrates. Several captions changed to say what the console actually
does.

**The showcase case is TLP:CLEAR now.** The README promised a CLEAR case,
but its own recipe could only make an AMBER one: `demo-network` hard-coded
the case's label, and graph writes default to AMBER.
`bootstrap.py demo-network --classification` sets the label for the case
and every node and tie in it. The default is still AMBER, and the README
recipe asks for CLEAR.

**`scripts/seed_readme_showcase.py`** runs after the other seeders and
gives the case enough to show what the README says. It seeds:
- exhibits linked to about half the graph, a custody log with a read and
  a verification, and a legal hold;
- one inferred tie, and a few non-person entities on structural edges;
- selectors, and comms bindings with a parsed contact block;
- triage proposals, one of them disputed;
- notifications from a second fictional account, and a break-glass grant
  awaiting review;
- analytics runs at three as-of dates;
- one GREEN exhibit, so a CLEAR report withholds something.

Everything is written through the services. A test proves that the social
projection's metrics for the fifteen identities do not change, because the
analytics paragraph depends on them.

**Copy.**
- Every em dash, en dash, spaced double hyphen and bracketed plural ending
  is gone from the console and from server strings a user can see. Tests
  now refuse all four.
- Counts agree in number, including in stored notification text.
- Times are printed the way the console prints them everywhere.
- The Lab says KiB, as the Evidence pane does.

**Fixes the screenshots exposed.**
- The Deception help described the Received chain upside down. The README
  paragraph did too.
- ACH's rule for an unfinished row contradicted its own warning.
- The analytics Trend showed when each run started, not the world time it
  measured. It now has an As of column.
- The report preview called its scope "the whole case" beside a smaller
  count. Its redaction statement also broke around its bold run, and it
  said "not recorded" for dates it had withheld.
- An exhibit's acquisition time came from the API host's clock, and its
  custody row's time from the database's. A database clock behind the
  host showed an exhibit acquired after its own ACQUIRED row. Both now
  come from the database.
- The Tox preview wrapped a key over two lines. Notification preference
  selects stretched across the pane. The canvas hint named the Mac key on
  every platform.
- Stale "Phase 3" copy, and copy written for developers, was removed.
- Search now says when a hit came through an attribute.
- The custody log names the person, not an id.
- The CI job installs the `dev` extra, so the QR reference encoder is
  present and the no-skip gate passes.

### A second review, of the merged result

A second review, of the usability fixes below taken together, found 43
more problems. Each was shown to be real before it was fixed, and all 43
are fixed.

**Security.**
- A report's competing hypotheses went out whatever the target level, and
  their cells read nodes and assertions above it. A RED case prepared at
  GREEN produced a TLP:CLEAR file naming the operation's suspect. The
  hypotheses now go only where the case header does (otherwise they are
  counted as withheld). Their cells are read at the reader's level, in the
  report and in `GET /ach`, and feed the document's mark.
- The one-time credentials card in Administration (password, TOTP secret,
  QR) survived sign-out and was shown to the next person to use the tab.
  It is cleared whenever a session ends or another account signs in.
- `defang()` left a bare host live when its query held `x://`.
- A case-scoped break-glass grant showed RED collected-document titles and
  source names in the inspector. Documents are every source's, so they
  keep the analyst's own ceiling.
- Accepting a proposal wrote elements at any classification the reviewer
  named. It is now held to their ceiling, like every other write.
- Report tables escaped nothing: a `|` in a handle moved the TLP column,
  and a line break in a label could add a `**TLP:CLEAR**` line.

**Break-glass.**
- A sole Security Officer could invoke a grant nobody else could review.
  It is refused, and the officers alerted exclude the invoker.
- A live grant can no longer be reviewed. The review judges everything
  done under it, and a verdict used to take it off the only list that
  could end it.
- The count, the invoke pane and both cards now say the same thing about
  what is counted.

**Preservation and readiness.**
- A rejection no longer holds the audit-chain lock across an S3 DELETE.
- A held copy written but not read back is reported as a copy that
  exists.
- A later record-only rejection cannot overwrite a preserving one.
- The preservation check now proves the LEGAL HOLD the samples rely on,
  not only COMPLIANCE retention.
- The probe fails when the store records GOVERNANCE for a COMPLIANCE
  request, instead of calling it proven.

**Console.**
- The Analysis pane, sociogram replies, saved layouts and typed entry
  forms no longer carry one case into the next.
- The break-glass chip notices a grant ending.
- Idle expiry is no longer postponed forever by live-channel refetches.
- The first-run sign-in leaves the sign-in form usable after sign-out.
- The edge inspector can add a claim, so a tie's confidence can be
  lowered without retracting the claim that carries its exhibit.
- Egress checks ask for a fresh sign-in, rather than calling an expired
  one a refusal.
- A real purge is bound to the dry run it confirms.
- Share shows role names and when a colleague's emergency access ends.
- An officer-only account's view is called Oversight.

**Search.**
- A pasted Gmail `+tag`, googlemail or IDNA address finds its selector.
- The trigram index 0065 added is now used.
- A merged record's name finds its survivor.

### The 2026-09-22 usability and code review, and the owner's decisions

The 2026-09-22 review of the console and the code behind it produced 229
verified findings (12 critical, 78 high, 105 medium, 34 low). This release
fixes 75 of them: all twelve criticals, 53 highs and the ten medium and low
findings that share their code. The other 154 stay on the review's list, in
`ROADMAP-REMAINING.md`. The fixes add migrations 0062 to 0065, so with
Wave 1's 0060 and Wave 2's 0061 an Alpha 5.2 database, which stands at
Alembic 0059, moves to **0065**.

**Owner decisions, recorded in docs/00 (61 to 64) and docs/17.**
- A rejected malware sample is preserved by default, not destroyed. Its
  encrypted bytes move, with the data key kept, into an object-locked
  store (`PRESERVE_BUCKET`, default `noctornal-preserved`) under a legal
  hold. Getting them back takes two people: the Security Officer
  authorises and the Lead investigator retrieves.
  `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=destroy` opts back into
  destruction, which a legal hold still refuses (0063).
- The Lead investigator reveals victim PII and the Security Officer alone
  authorises it. Break-glass is invoked by the Lead investigator or the
  administrator and reviewed by the Security Officer alone. Both pairs are
  separated duties, so no role can hold both halves. The upgrade revokes,
  with an audit event each, any authorisation a Lead investigator granted
  a co-lead (0062).
- `CASE_OWNER` displays as **Lead investigator**. The key is unchanged, so
  no permission check moved.
- The archived MinIO build stays pinned, with the risk accepted in writing.
  The readiness register no longer reads the bucket's lock configuration;
  it proves write-once. It writes a canary under a one-day COMPLIANCE
  retention and passes only when a delete that names that version is
  refused, on both the evidence and the preservation buckets.
- The placeholder retention periods are a deployment setting, which the
  register already blocks on. They are no longer listed as a defect.

**The sociogram.**
- The hollow "unevidenced" mark had never drawn. It now uses area and is
  never a fade, because opacity is reserved for confidence.
- A tie's confidence comes from one place: its strongest live assertion.
  Migration 0064 backfills the ties whose stored value disagreed, and
  writes no audit event for them. That includes raising a tie an analyst
  had lowered with a correction beneath a claim that is still live. The
  upgrade notes above give a query to run before upgrading, which records
  every tie it will change, and one to run after, which lists the lowered
  ties for an analyst to look at again.
  The confidence picked on Add relationship now reaches the tie; before,
  every new link was stored as LOW.
- Parallel ties bow apart, and `[` and `]` step through them.
- Fit frames the whole case.
- Labels thin out by priority instead of vanishing below 0.7x.
- Add relationship no longer pre-selects an accusation or pre-grades a
  claim, and the endpoints can be searched.
- A selected entity offers Link from and Link to.

**Evidence.**
- "Evidenced" has one definition. The canvas, the coverage figure, the
  report column and the inspector all use it.
- A failed hash check shows as a red HASH MISMATCH, no longer as a grey
  "not checked".

**Search.**
- Entities are found by the selectors attributed to them (wallet, Jabber,
  Tox, email, handle), exactly or in part, with the matching selector
  named (0065).
- Fragments of handles, domains and file names match.
- A capped list says how many matched (`with_total`).

**Lab.**
- The state filters work.
- Reject names the sample and says what will happen to its bytes.
- Inside a case, the queue is that case's samples.
- The custody ledger says who did what.

**Deception.**
- The capture and email detail cards were never visible. They are now.
- URLs in an email body are defanged.
- Analyst notes render.

**Governance.**
- A break-glass grant from the console raises what it names, on the open
  case. A header chip stays up while any grant is live. Starting or ending
  a grant reloads the open case.
- Review cards name the people involved. A verdict is confirmed before it
  is recorded, because the server will not revisit it.
- Purge is a dry run by default. A real purge confirms by case code and
  names what the dry run counted.
- Sharing names people rather than ids.
- Administration is reachable without opening a case.

**Reports.**
- A report file now comes only out of the egress release, so it has been
  judged at the gate.
- The console will not save a cleared document whose `content_digest`
  differs from the one previewed.
- `POST /report` refuses `fmt=markdown` and points to the release.

**Case switching.**
- Search, Report, Feeds, Triage, Comms, the Lab and Deception drop
  the previous case's results.
- A reply that lands after a switch is discarded.
- A load that fails says so and offers Retry, instead of reading as empty.
- The header shows the case's state.

**Dates.**
- Every time on screen is UTC and says so.
- A date-only value is a calendar day and no longer shifts a day west of
  UTC.

**First run and session.**
- The one-time credential card keeps the password and authenticator
  secret until they have been used, or until the operator confirms losing
  them. It shows a QR code.
- Recovery codes can be obtained from the account panel.
- Idle expiry warns five minutes ahead. Signing in again carries on in
  the same case, pane and form, and says whether the last action saved.

### A destroyed data key is not an unopenable one

Destroying a rejected sample (the only disposition until the review pass
above, and now one a deployment must declare) destroys its data key along
with the bytes it opened, deliberately, so that nothing can decrypt the
object if it survives a bucket-lifecycle race. `lab.sample.data_key_ciphertext` is NOT NULL, so
"the key is gone" is recorded as zero bytes.

The key-ring inventory counted those rows as sealed material and handed
them to AES-GCM, which rejected the empty nonce with a `ValueError` that
was not in `envelope.UNOPENABLE`. It escaped every caller that had asked
only whether a blob opened. One rejected sample was enough to take the
whole `kek_ring_opens_stored_secrets` readiness check out, so the register
reported an exception where it should have reported on the key ring, and
said nothing about the ring at all.

`rewrap_secrets.py --apply` hit the same rows in its `--legacy-key-file`
mode, which visits every row rather than only those under a retired id,
and aborted mid-pass. That is the recovery tool, run under pressure after
restoring a key.

Fixed at the root: `MalformedBlob` names the third way a stored secret
fails to open and joins `UNOPENABLE`, so a short blob is reported rather
than raised, and an empty ciphertext is excluded from the inventory and
the rewrap because it is the absence of a sealed row, not a broken one.
A login against a malformed secret now answers 503 naming the readiness
check, as it already did for a missing or wrong key.

### The installer had never been run on a clean machine, and did not work

`release/INSTALL.md` promises the installer "checks what it needs and
tells you exactly what to do if one is missing, rather than failing
halfway". That had never been tested anywhere except a development box.
Run on a VM built for it, Ubuntu 24.04 from the official cloud image with
nothing added, it failed halfway three times. `release/CLEAN-VM-INSTALL.md`
records the run.

**It could not build a virtual environment on any stock Debian or Ubuntu.**
A guard for this existed and asked the wrong question: `import venv`
succeeds there, because `venv/` ships in `python3-minimal` while
`python3.12-venv` carries the `ensurepip` that actually creates the
environment. The guard passed, said nothing, and the install died two
steps later inside `python -m venv`, in Python's voice rather than its
own. It now asks for `ensurepip` and names the versioned package, derived
from the interpreter it selected.

**The failed environment was then mistaken for a good one.** A failed
`venv` links `bin/python` before it dies, and the "already built" test was
`-x "$VENV_PY"` alone. So the second run reported `.venv already exists`
and died with `No module named pip`, a message further from the cause than
the first run's, which never again mentioned the real fix. Installing the
package the first run named did not help; only `rm -rf .venv` did, and
nothing said so. The test now requires `bin/pip`, a half-built environment
is named and rebuilt, and a failed `venv` removes its own wreckage.

**Every non-interactive install died silently at the account prompt.**
`docker compose exec` forwards the parent's stdin to the container even
with `-T`, which disables the TTY and not the attach, so sixty iterations
of the Postgres readiness loop drained whatever the installer was given.
`read` then hit EOF and returned non-zero, and under `set -e` the script
ended there, before the branch written to handle empty answers. The user
saw the output stop mid-sentence at `Email: `, with exit 1 and no message.
Anyone at a keyboard was fine, because a pty does not reach EOF, which is
why it stood. Fixed by redirecting the probe's stdin and guarding both
reads, which is also what makes that fallback branch reachable at all.

Two smaller ones: the generated `.env.local` omitted the upload caps, so a
new install carried a readiness warning and could not be promoted to a
production deployment without meeting a boot refusal; and the shell scripts
shipped `100644`, so `./release/install.sh` answered "Permission denied".

All five are fixed and re-verified on the same VM. A single run with a file
on stdin and no terminal now installs and serves: migrations to `0061` (the
head that day), an
account with password and TOTP, `/ui/` answering 200. Five static checks in
`test_script_invariants.py` hold them, in the same style as that file's
existing installer tests, because nothing here is reachable by running the
suite.

### MinIO's open source is archived, and CI found out first

CI went red on a commit that changed documentation and nothing else. The
step that failed was `Start MinIO`, in one second, which is a pull failure
rather than a readiness timeout. Reproduced on the build machine the same
day: `docker pull minio/minio:latest` answers **"pull access denied for
minio/minio, repository does not exist or may require 'docker login'"** to
an unauthenticated puller, on a host that had pulled that image a week
earlier. `minio/mc:latest` is gone the same way.

This is the second time an unpinned MinIO image has done this. The CI file
already carried a comment about the first: `bitnami/minio:latest` stopped
resolving on 2026-07-26 when Bitnami moved their catalogue, and the fix
then was to switch to Docker Hub's own `minio/minio:latest`, which is the
image that has now gone.

All four references (the CI step, and the server and `mc` images in both
compose files) now pull from **quay.io, which MinIO publishes to directly,
at a pinned RELEASE tag**. Both were verified by pulling and running them,
and the development stack was recreated on them: buckets created, object
lock configured, full suite green at 2519 passed. `latest` is what both
outages have in common, so neither pin is `latest`.

**Then the repin failed on the next step, and that is the real finding.**
CI fetched `mc` from `https://dl.min.io`, which now answers 410 Gone: *"The
open-source MinIO Server, MinIO Client (mc) and MinIO KES projects are
archived and no longer maintained. MinIO does not provide product support,
security updates, or security advisories for them, and does not accept or
process vulnerability reports concerning them."* `curl` without `-f` saved
that notice as the binary and exited 0, so the failure surfaced sixty
seconds later as thirty alias retries rather than as a download error. The
step runs `mc` from the pinned image now, through `MC_HOST_local` because
each `docker run --rm` is a fresh container and an alias would not survive
to the next one. Rehearsed locally against a throwaway MinIO on the port CI
uses: three buckets, GOVERNANCE 365d on evidence, and no lock on samples,
which is what docs/11's destruction path requires.

**The archiving itself is the owner's decision, not a CI chore.** The WORM
guarantee under every exhibit in this system now rests on software that
will receive no security fix, and that is a sentence a disclosure process
will eventually ask about. It is recorded as `docs/17` F24, with the three
options and their costs, and against `docs/16` C2, which is the
confirm-externally item it changes. Nothing is broken today and nothing
here should be settled by whoever next sees a red build.

### The documentation pass

Two thousand lines lighter, with nothing true removed.

**Four documents were doing no work.** `TestFlight.md` was a dated record of
installing an artefact three releases old, at 52 migrations and 1269 tests,
whose three defects were all fixed within the week; the procedure it followed
is `release/INSTALL.md`. `db/concept/` was a 467-line SQL sketch for comms,
the lab and ingest, all three of which shipped and migrated past it, and it
had already misled one reader: the 2026-07-25 survey reported the write-only
ingest constraint as concept-only when it had been live since migration 0033.
`db/seed_ontology.sql` was a third copy of the ontology, marked REFERENCE
ONLY and asking to be kept in sync by hand; measured, it was 6 node types, 22
edge types and 44 selector types behind the generated seed and held nothing
the generated one lacked. All three are gone.

**Two registers had become archives.** `ROADMAP-REMAINING.md` was 1,020 lines,
of which perhaps 150 said what was left; the rest was nine dated narratives of
review passes, and a table of nine gaps every one of which was marked closed.
`docs/17-flagged-for-review.md` was 717 lines, over half of it entries that had
been fixed. Both now carry what is open, and the closed entries survive as a
one-line index each with the date that closed them. The history they held is in
this file, which is where a dated record belongs.

**Three documents were nearly deleted and should not have been.**
`docs/02-architecture.md`, `docs/09-roadmap.md` and `docs/14-enhancement-map.md`
looked like duplicates of ARCHITECTURE and the roadmap. They are cited 85 times
by the code as the provenance of a rule: `docs/14 U2` is why an under-cleared
analyst is told that something was withheld, and eight call sites say so. They
were restored and cut instead, to the brief, the phase exit criteria and the
enhancement items, and the division of labour is now stated at the top of each:
docs/02 is what was specified and why, `ARCHITECTURE.md` is what was built.

**Every em dash and en dash is gone,** 1,272 of them, replaced by the
punctuation the dash was standing in for: a full stop where an independent
clause followed, a comma for a qualifying phrase, a colon before a definition,
parentheses for an aside, a hyphen for a range. Three passes were needed. The
first classified line by line, and these documents are hard-wrapped, so it read
the clause after a break as a phrase when the verb was on the next line. The
second bounded a block at a blank line, so an aside opened inside one bullet and
closed inside the next, leaving a parenthesis unbalanced. The third reads whole
blocks, bounds them at list items and table rows, refuses to touch code, and
asserts that the parenthesis count it changed is balanced.

**And the stale claims each of those exposed.** `docs/10`, `docs/11` and
`docs/12` still opened with "Status: concept. Not implementation-ready." for
three phases that had shipped. `docs/17` still listed login timing
equalisation as deferred, a year after a test pinned it, and the deferred table
described the API as connecting as the table owner, which the production
deployment stopped doing in Wave 1. `docs/02` said there was no production
manifest. `ARCHITECTURE.md` cited two documents by line number, and said
`docs/16` holds **four** blocking legal items where it holds five: the same
undercount the 2026-07-26 correction caught in the roadmap and the counsel
pack, still sitting in the third document.

**And one the pass caused and then caught.** The generated head counter
matched `` `0001`-`0061` `` through a fixed-width lookbehind on the en dash,
so removing the dash turned that check off silently. Repairing it found
that the same pattern had never matched the prefixed form,
`` `db/migrations/versions/0001`-`0061` ``, which had been quoting 0059 on a
0061 tree the whole time. A counter written in a shape nothing checks is the
defect this tree keeps finding in itself; this is the third instance.

### Roadmap items 8 to 13: a size policy, a key ring, a refusal, one alpha, and the gate on dead letters

**8. The exhibit size cap is a declared policy.** It was a module constant
(256 MiB, changed by editing source) on an upload whose every accepted
byte is locked under COMPLIANCE for the retention period, which is a
decision about a permanent commitment nobody in the deployment had taken.
`NOCTORNAL_MAX_EVIDENCE_BYTES` declares it (bytes, or `512MiB`), read once
by the router through `config.declared_cap`; a production boot refuses
without it, and refuses either cap declared unusably; the readiness check
`evidence_size_cap_declared` reports what THIS process enforces and says
"restart" when the environment has been edited underneath it; the console
reads `GET /cases/{id}/evidence/policy` once and prints the cap beside the
picker, and refuses a larger file before the upload starts (the server
stays the authority). The sample cap is declared the same way
(`NOCTORNAL_MAX_SAMPLE_BYTES`, on `/samples/policy`), without the boot
insisting, because that bucket is not locked. docs/08 owns the policy and
says what to do above the cap: not split the exhibit.

**9. The envelope's `key_id` selects a key.** It was written beside every
blob and read by nothing: `decrypt` accepted it and used the one
environment key regardless, docs/05 promised a rotation runbook nothing
could run, and a KEK that changed under a live database surfaced as an
`InvalidTag` out of a login (a 500 to the analyst) while the register
stayed green because its only KEK check asked whether the value was 32
bytes. Now a ring: `NOCTORNAL_TOTP_KEK` is the active key under
`NOCTORNAL_TOTP_KEK_ID` (default `env:v1`), `NOCTORNAL_TOTP_KEK_RETIRED`
holds `id=base64` keys that only open, and `decrypt` selects by the
blob's recorded id. The readiness check `kek_ring_opens_stored_secrets`
opens up to a thousand rows per (table, key id) across the five sealed
columns and COUNTS, because before the ring every blob was recorded as
`env:v1` whatever key sealed it, and one row's verdict is not a group's.
It says which of the two faults it found: no key of that id, or a key
of that id that does not open the blob. Login answers **503 by name**
(`AuthOutcome.SECOND_FACTOR_UNAVAILABLE`), after the password verified,
burning no lockout attempt and naming the check. `scripts/rewrap_secrets.py
--apply` re-seals every row under the active key, compare-and-set per row,
and `--legacy-key-file` brings home rows a pre-ring key sealed under the
same id. The four-step runbook is in `security/envelope.py`, the template
and the production README.

The development database this was written against is the case the check
exists for: 93 enrolled accounts and 153 samples, all `env:v1`, of which
65 accounts and 69 samples opened under no key on the machine: test
rows left by killed runs on 2026-09-10, sealed by a `.env.local` that has
since been regenerated. The register on that machine is red on the new
check until they are deleted, which is the correct answer; CI's fresh
database is green. The ring test rotates AWAY from whatever key it finds
and back again in a `finally`, so it can run on that database too.

**10. A bare positive Telegram id is refused.** docs/17 F1's residual
since 2026-07-26: `1234567890` was assumed `u:` on a strong selector, so
an MTProto channel observed as a bare number merged with a same-numbered
user. `telegram_id_norm` now returns nothing durable for it and
`noctornal_ontology.refusal()` says why in one sentence naming `u:<id>`
and `c:<id>`. It is the sentence `SelectorStore` raises, `comms.normalise`
returns as its note (it also accepts the typed forms now, which it did
not), and the contact-block parser records beside an unresolved
`Telegram:` line. Closing it exposed a hole beside it: `SelectorStore.
record` stored whatever the normaliser returned, and for anything it
could not reduce that was `''`: one row per case per type for every
unreducible observation, a merge lead between strangers on a strong type.
An empty canonical form is refused. Rows typed by assumption before today
keep their `u:` (nothing can recompute a type that was never observed);
`scripts/telegram_bare_ids.py` lists them per case.

**11. The canvas dims by the theme's steps.** `confAlpha` in app.js
carried its own 1 / 0.72 / 0.45. The theme had raised `--conf-low` to 0.58
for contrast (Alpha 5) and the sociogram never noticed, so the inspector
printed one opacity and the edge was painted at another, and docs/06
still said 0.45. `loadPaint` reads the three tokens through `cssVar` like
every other painter, `paintIsComplete` reports one that does not resolve,
and a test holds app.js, theme.css and docs/06 to one number.

**12. The dead-letter listing's decisions are `evaluate()`'s.** `GET
/ingest/dead-letters` decided access three ways of its own: a SQL
restatement of `require_global`, a SQL restatement of four of the five
case checks, and label predicates in the query. Each was correct on the
day it was written, and every authorization defect this tree has shipped was a
query that never called the gate. `PgAccessResolver.resolve_global`
resolves a global verb into an `AccessContext` (the relationship check
satisfied by construction, stated); `_holds_global` reads the verb and
step-up checks off the decision; the caller's cases are the ones the gate
allows one at a time; and every RETURNED row is put to the gate against
its own labels, through its case or through the global verb for an
unattached row. The SQL predicates only bound the fetch. Three tests
replace `evaluate` with a verdict of their own and watch rows appear and
vanish with it.

**13. One scheduler, one adapter: "only if you collect".** The
scheduler half is Wave 1: the cron sidecar in the production compose runs
`scripts/collection_poll.py` on a five-minute resolution and each source
keeps its own jittered cadence. The adapter half is unchanged: RSS is the
one adapter, and XenForo/MyBB/Telegram stay behind docs/16 L3 and the
owner's own condition on the item. Not built, and said so rather than
built untested.

**Also.** `scripts/refresh_counters.py`'s head pattern was a lookbehind on
a single space, and the roadmap's live paragraph wraps between "head" and
the number, so that one paragraph said `0060` on a `0061` tree while every
other document was held exactly: the defect the tool exists to kill,
inside the tool. The pattern crosses a line break now.

### Wave 2: the console holds no credential

The console kept the login-body token in page memory for exactly two paths
that could not read the cookie: the live websocket, which authenticated
from a token in its first frame, and the Lab download, which is
cross-origin so no `__Host-` cookie can reach it. Both are closed, and the
login response no longer carries a token at all.

**The websocket takes the cookie.** `ws.cookies` is readable on an upgrade
and the cookie value IS a session token, so `_handshake` prefers it and
keeps the first frame only for `scripts/bootstrap.py session`, which mints
in a shell and has no cookie jar. A browser cannot set a header on an
upgrade, so the CSRF double-submit is impossible there; `SameSite=strict`
plus an explicit `Origin` check refused before `accept()` is what stands in
its place. Measured in a browser: sign in, open a case, reload, reopen.
The dot stays live, `sessionStorage` and `localStorage` are both empty, and
the only cookie script can see is `__Host-csrf`.

**The Lab download is a one-shot ticket.** Minted on the application origin
under the cookie session, so the double-submit applies to the mint; stored
as a hash (migration 0061, `lab.download_ticket`); redeemed exactly once by
a single conditional `UPDATE`, so two simultaneous redemptions cannot both
win; sent in the POST body rather than a URL, because a URL reaches the
access log, the Referer and the history. Sixty seconds, because it is a
hand-off between two requests the browser makes back to back.

**Then the token went.** `POST /auth/login` answers 204 with the cookie
pair and nothing else. `deps.session_token` still accepts a Bearer, which
is how a script client and the `#token=` hand-off work; what is gone is
login handing one out. Twenty-seven test files that read the token from
that response now mint a session directly, the way `bootstrap.py` does.

**What the review caught, and it was not small.** Sign-in was completely
broken: `doLogin` still read `out.token` from a response that had become a
204, `_fetch` returns null for a 204, and every form sign-in threw, was
swallowed by the catch, and told the analyst "Unexpected error" while the
server had in fact signed them in and set the cookies. There is now a pure
test that login answers 204 with no body, which nothing had covered.

Two security defects were closed after the first pass. The redemption
audited every failed presentation including one that matched no row (a
path reachable on the sample origin with no credential at all, writing into
an append-only hash-chained log), so an unknown ticket is now a sampled
warning and the route carries a named rate limit. And the redemption
re-checked the sample's labels but not the ACCOUNT, so inside the
sixty-second window a deactivated analyst still got the archive; it now
re-derives the account and the permission, and the residual is stated
exactly where it is bounded.

A third finding predates this wave: `/api/v1/live` is routable on a process
configured as the sample origin, because the middleware that makes that
process serve bytes and nothing else never runs for a websocket scope. The
upgrade is refused there now.

**A control that would have shipped silently broken.** The `Origin` check
compared only against the configured origin. The shipped launcher binds
`127.0.0.1:8000`, `NOCTORNAL_BASE_URL` keeps its matching default, the
console is opened at `localhost:8000`: two genuinely different origins,
correctly distinguished, and the result was that every live socket was
refused for every developer, before `accept()`, which reaches a browser
with neither code nor reason. It was found by opening the console, not by
reasoning. The rule now also accepts the origin the request arrived on,
which is the ordinary same-origin test, needs no configuration, and is not
weaker: a cross-site page cannot make `Origin` and `Host` agree.

**Known.** The one residual on the ticket is stated in `0061` and in
docs/17 F22: a ticket minted under a session revoked inside the following
sixty seconds can still be redeemed, by a holder whose account is still
active, still permitted, and for a sample they may still read. When this
wave landed, a `NOCTORNAL_TOTP_KEK` that did not match the one an account
was enrolled under made `POST /auth/login` answer 500, and the
`totp_kek_set` readiness check could not see it; the key ring above closed
both on 2026-09-11.

### Wave 1: it can be deployed as a service rather than run as a script

Until now the only way to run this was `scripts/launch.ps1` on a laptop:
one uvicorn process bound to loopback, the schema's owner as the database
role, the object store over plain HTTP, and a compose file whose first
line says not to derive a deployment from it. There was no Dockerfile in
the tree at all.

**`infra/production/` is the real one, and QUICKSTART now says so.** One
host, docker compose, no orchestrator. Caddy terminates TLS for the
application and the sample origin and is the only thing that publishes a
port; Postgres, Redis and MinIO are reachable only on the compose network.
A one-shot `migrate` job runs Alembic as the schema owner and everything
else waits for it. `infra/production/README.md` is the operator procedure,
including what this deployment still does not give you.

**The API no longer owns the tables it writes.** `noctornal_app` is
created at initdb (the only place `CREATE ROLE` can live, since this
tree forbids the migration role from being a superuser), and migration
0060 grants it. Verified against a running stack: the API connects as
`noctornal_app`, `core.node` is owned by `noctornal`, and
`ALTER TABLE audit.event DISABLE TRIGGER USER` comes back **"must be owner
of table event"**. That is the append-only audit and custody chain
defended by the database rather than by the application's good manners.

0060 is a complete no-op when the role is absent, because ten `*_pg` test
files need ownership to run `ALTER TABLE ... DISABLE TRIGGER`, and CI runs
both the upgrade and the downgrade round trip. CI creates the role by
running `db/init/10-app-role.sh` itself, so the ten new privilege tests run
there rather than skipping.

**A production process refuses to start on a development secret.**
`config.verify_environment()` reports every problem at once, each with what
it costs, and only when `NOCTORNAL_ENV=production`: a laptop and CI are
untouched, which is why the check is still there in a week. Measured: a
container given `dev_only_change_me` in its DSN, `SMTP_ALLOW_PLAINTEXT`
and `NOCTORNAL_ENABLE_DOCS` names all three and does not boot.

**The readiness register now refuses a quiet green.** Four of the thirteen
checks are blocking, `report()` carries `blocking_failures`, and two things
consult it: `POST /collection/sources/{id}/run` answers 409, and so does
the unattended cron path. The second was added after the first, in this
same change: a gate on the attended route only would have let the cron
poll real sources on a deployment whose blockers were red, which is
precisely the claim the tier is making. Two new
checks: `ingest_pepper_set` and `app_db_role_not_owner`.

**The sample origin is a compose service.** The same image, a second
process, its own hostname. Verified: `origin_split()` answers `app` on one
and `sample` on the other, from the server process's own environment.

**Things that run on a timer now run.** A `cron` service runs
`scripts/notify_drain.py` and the new `scripts/collection_poll.py`. The
collection runner respects each source's jittered `next_due_at` rather than
imposing a cadence (docs/04 and docs/18 both name a scheduler on a
regular tick as an operational-security failure), and a new per-source
advisory lock stops two runners corrupting one source.

**Known, and not fixed here.** No real SMTP relay exists on the build
machine, so "a priority-1 notification leaves the building" is the one line
in this wave that is wired and documented but unproven. When this wave
landed, the websocket and the Lab download still authenticated from the
login-body token and a reloaded session was not live; Wave 2 above closed
all three. `docker exec` does not inherit a variable exported inside a
container's entrypoint, which made two verification probes report
failures the deployment did not have. Both were the probe, and
`/proc/1/environ` is what to read instead.

## Alpha 5.2: 2026-09-10

The b-revision of Alpha 5.1, closing what a re-read of it found. Alpha 5.1
wrote a linter for the previous review's examples; this closes the classes
those examples belonged to.

### The counters are generated, and the tolerance is gone

`test_doc_invariants` allowed a quoted test total to sit within five per
cent of the tree. At this size that is eighty tests of slack, and Alpha
5.1 shipped a README claiming 1627 against a tree of 1639, stale, and
green, because the drift fitted inside the band. `scripts/refresh_counters.py`
now writes every live counter (tests, revisions, Alembic head, version,
completion) from the tree, the test asserts that running it would change
nothing, and the tolerance is zero. Same arrangement as `db/schema.sql`.

Two numbers that nothing can derive are gone rather than unchecked: the
"collected items" totals, which need a pytest collection, now live only in
these per-release entries, where they are dated records of one run.

### The invariant tables are held to each other

Alpha 5 reworded invariant 7 in CONVENTIONS and ARCHITECTURE, credentials
never leave the **vault**, which runs inside the API process, because there
is no collector. The README's table, the one a new reader meets first, went
on saying "never leave the collector, decrypted only in the worker process":
two processes this build does not have, on the front page, under a linter
that was looking for the removed `sigma.js`. All three statements of each
invariant are
now held to a distinguishing word, so a row reworded into something the
tree does not do fails whatever it was reworded to.

### Behaviour that was designed and never built

Auto-merge survived the Alpha 5 pass in the ontology definition, the
Telegram normaliser, the generated TypeScript, a comms test and the README,
all describing it in the present tense. A strong-selector collision raises
`StrongSelectorConflict`, a merge *lead* an analyst confirms. The register
that catches this now reads source and tests as well as prose, and carries
its maintenance rule: when a decision record says a thing was never built,
add it here.

### Smaller, same shape

- `retract_assertion`'s own docstring still said "history is superseded,
  not overwritten" above the stamp-in-place UPDATE that Alpha 5.1 decided
  was a marked row.
- `apps/api/pyproject.toml` described itself as "Session 3 lands
  authentication", packaging metadata of a 0.5.1 release, in no linter.
- README claimed 59 revisions "all reversible". They are reversible on an
  EMPTY database, which is what the round-trip test proves; a downgrade
  past `0017` on a populated one is refused on purpose.
- README sold COMPLIANCE-mode WORM without saying the shipped compose file
  sets the bucket DEFAULT to `GOVERNANCE 365d`. The per-object COMPLIANCE
  lock `EvidenceStorage.put()` applies is the guarantee; the bucket default
  is the floor for anything written by another path.
- Three overall completion figures (92.8%, ~92%, ~95%) are now one, and
  only `ROADMAP-REMAINING.md` works it out.

**Known.** The first run of `refresh_counters.py` rewrote two dated records
it walked past: "it had 673 passing tests" and "surveyed at revision 0052".
Both were restored, the shapes were narrowed to four-digit totals and the
`Alembic head` phrase, and the tool now prints every line it changes. A
generator loose in prose is a new way to lose history, and it is on the
first page of that script.

The Redis GCRA agreement test still fails on the development box every run
and passes on CI: clock drift between the WSL container and the host, and
the injected-clock refactor is still owed.

## Alpha 5.1: 2026-09-09

Follow-up release. **Still not audited, and still not lawful to operate
against real material until the five blocking items in
[docs/16](../docs/16-legal-and-external.md) are settled by somebody
outside this codebase.** Eight items from the owner's review of Alpha 5,
each with a test that fails on the tree as it was:

- Body caps: `POST /samples` and `POST /cases/{id}/deception/emails` are
  enforced by `BodyCappedRoute` at the ASGI receive, like evidence. The
  routers' private chunked reads, which ran after the multipart parser
  had spooled the whole body, are gone.
- The CSRF double-submit compares in constant time (`hmac.compare_digest`
  over bytes; a non-ASCII header is a 403, not a TypeError).
- The login audit hashes the address the session is bound to
  (`client_ip`), not the proxy's.
- The command palette offers every pane the rail has, in rail order; a
  test holds the two together.
- Invariant 5 decided: a retraction is a marked row, stamped once, not a
  supersession; a test pins that nothing else on the row changes.
- One session story across QUICKSTART, ARCHITECTURE and SECURITY: the
  cookie is the session; the login-body token is an in-memory,
  login-lifetime capability for the websocket and the Lab download until
  those two paths accept the cookie.
- CONVENTIONS no longer claims an implemented auto-merge or cursor
  pagination, and counts 59 revisions. README refreshed (live CI badge,
  Canvas 2D, 1627 tests, 59 revisions, generated `db/schema.sql`) and now
  held by `test_doc_invariants.py` like every other document.

**Known.** CI on the release commit: 2273 passed, 0 skipped, on a fresh
database. On the development box the Redis GCRA agreement test
(`test_redis_and_python_agree_request_for_request`) fails at its usual
iteration 23 every run, clock drift between the WSL container and the
host, the injected-clock refactor still owed. The samples positive
control leaves one quarantined 64 KB `cap.bin` per full-suite run in a
reused database, because a submission writes to the append-only access
ledger and can never be deleted; the same residue policy as custody.

Not in this release, by decision: the cookie pair on the websocket and
the sample origin, a `key_id` that selects a KEK, a COMPLIANCE bucket
default, the Telegram bare-positive refusal, the confidence-threshold
alignment, RLS under a non-owner role, a collector process (and
nothing of L1 to L5 in software).

## Alpha 5: 2026-09-09

Review release. **Still not audited, and still not lawful to operate
against real material until the five blocking items in
[docs/16](../docs/16-legal-and-external.md) are settled by somebody
outside this codebase.** Nothing in this release touches those.

An external product review of Alpha 4 was accurate on every point checked.
Its recurring finding was this codebase's own signature defect: a
document, docstring or counter claiming something the code does not do.
This release answers its first two tiers.

### The documents describe the program that exists

Eight documents still described the July sketch, every piece of it removed
or never built: Next.js (removed), OpenFGA and SpiceDB (removed),
NATS and Celery (removed), three trust zones (superseded), a sigma.js
WebGL sociogram (replaced by Canvas 2D), UUIDv7 (not in the tree).
The tree has been one FastAPI process on Postgres 16 with a
vanilla console under a strict CSP, a Postgres access gate and a Canvas 2D
sociogram since August. Every live description now says so; every
reversed decision keeps its history with a dated superseded-by note; the
launch scripts no longer announce containers that do not exist; and a test
refuses any new mention of the removed stack unless the line marks it as
history. `README.md` is the owner's and was left alone.

The version is single-sourced from `pyproject.toml` (it said 0.1.0 while
the package said 0.4.0). `db/schema.sql` is generated from a migrated
database and diffed in CI. It had named five of eleven schemas under a
docstring calling it a mirror. Test and migration counts are dated
snapshots held to the tree by a test, and a document that quotes an
Alembic head must quote the real one.

### Before any second analyst

- **ACH cells can be scored from the console.** The stance route had
  existed since Phase 6 with nothing calling it. Each evidence × hypothesis
  cell opens a chooser showing the assertion's Admiralty grading and the
  five-point stance scale; the ranking re-renders on save.
- **Recovery codes can be typed.** The login field admitted six digits
  only, so the documented clock-skew fallback was a bootstrap script that
  bypasses MFA.
- **The console uses the cookie session.** `__Host-session` is HttpOnly
  with a readable CSRF half; nothing is written to web storage; logout's
  cookie deletions carry `Secure`, which browsers had been ignoring. A
  `#token=` link can no longer replace a session the browser already holds
  (it did, browser-wide, in the first cut of this change, caught by the
  adversarial review), and the server refuses to adopt a cookie for a
  different account with a 409 and an audit row. The websocket still
  authenticates from a token in its first frame, so a session restored
  from the cookie is honestly "not live" until the next sign-in, and says
  so.
- **Two `labelOf` functions became one.** The second silently shadowed
  the first, and projection-only nodes printed `null`.
- **Bodies are capped before they are buffered.** Evidence uploads had no
  cap at all onto a COMPLIANCE-locked bucket; ingest checked its cap after
  buffering the payload. Both now refuse with 413 before the bytes
  accumulate.
- **The dead-letter listing is scoped** to what the caller can read; it
  had listed every case's failures to any holder of global `ingest.read`.
- **The sample-origin check is decided by configuration, never by the
  Host header.** It had compared against `request.url`, which Starlette
  builds from a client-supplied header, and was unsatisfiable from a
  console whose CSP allowed only its own origin. Three variables and five
  verdicts now decide it; the UI CSP names the sample origin; unset means
  the control is OFF and every download refuses, in the readiness register
  and in every document that describes it. The sample origin is a second
  process of this code, a deployment decision recorded, not made.
- **The persona status write has a ceiling and checks its rowcount**; it
  had burned a RED persona for any holder of the global verb who knew the
  id, and returned 200 for an id that did not exist.
- **Credential-free websocket handshakes are refused before `accept()`**
  and bounded per peer. The first cut refused after accepting, which under
  uvicorn's websockets backend let a hostile peer hold the transport for
  ten seconds uncounted, measured, not reasoned, by the review that
  caught it.
- **Migration 0059 binds every compartment column, and the ingest key's
  forced compartment, to the registry.** A raw UPDATE or a psql typo can
  no longer file material under a compartment nobody registered. The
  migration refuses to run over legacy values and prints the cleanup.
  Eleven test fixtures and the demo seeder had been writing unregistered
  keys, several passing only because an earlier file left the key behind;
  each now registers what it writes.

### The hygiene checker was vacuous from a worktree

`scripts/check_source_hygiene.py` matched its skip list against absolute
path parts, so from any checkout under a `.claude/` directory it scanned
nothing and reported a clean tree. It now compares in-tree paths and
refuses an empty scan. It also fails the build on the owner's private
alias, which shipped on the licence page of three releases before this one.

### Known

The suite is not order-independent on a reused database (see Alpha 4).
`test_ratelimit_redis::test_redis_and_python_agree_request_for_request`
fails deterministically on the development box and has since July; its
docstring records the injected-clock refactor it needs.

Full suite on the release commit, both pytest roots, migration 0059:
**2255 passed, 3 failed**, that Redis flake, and the two version-contract
tests, which failed in the recording run because the version was bumped
while it ran and pass on the final tree.

## Alpha 4: 2026-09-02

Completion release. **Still not audited, and still not lawful to operate
against real material until the five blocking items in
[docs/16](../docs/16-legal-and-external.md) are settled by somebody
outside this codebase.** Nothing in this release touches those.

This one closed gaps rather than adding surface, and most of what it
closed was a control that existed and could not be reached, or a sentence
that claimed more than the code did.

### The custody ledger is verified for the first time

`core.evidence_custody` has been hash-chained since migration 0024, under
a docstring invoking FRE 902(13), (14), and nothing had ever recomputed
it. The internal audit log had a verifier, a CI step and a UI button; the
record actually produced to a court had none of the three.

It now has all three: `custody_verify.py`, `GET /audit/custody/verify`
under `audit.read`, a CI step beside the audit chain, and a control in
Governance → Audit chain. It checks LINK, CONTENT, FORK and GENESIS
across the whole ledger, and because the chain is global, naming an
exhibit narrows what is *reported* and never what is checked. The scoped
answer says so rather than reading like a completeness pass.

**What it still cannot see is a tail truncation.** Deleting the newest
rows orphans nothing and needs no rehash, so the ledger still agrees with
itself. That is the first entry in the module's own list of what it cannot
see, and the response carries `last_id`, `checked` and `tail_row_hash` so
an operator recording them out of band can catch a decrease. A run-to-run
equality check on the hash is *not* the defence it looks like (the hash
changes on every honest append) and the docstring says which two checks
do work.

### Break-glass raises something

Since Alpha 3 the grant is read by `PgAccessResolver.resolve()` and does
what its docstring always promised. `record_use()` is called only when the
grant is what made an access possible, so the security officer's review
queue counts accesses the grant actually bought rather than a constant
zero.

### Controls that existed and could not be reached

- **The readiness register** (`GET /admin/readiness`, and an Admin
  section) answers what this deployment can establish about itself, with
  the evidence beside each line. It is the code-side half only: the
  docs/16 items that need a human are named as out of scope, and two items
  it *can* partly check say so in their passing evidence rather than
  leaving the operator to infer it.
- **The delivery ledger**, `notify.delivery` has recorded every refusal
  since 0029 and every destination since 0044, and nothing read it. There
  is now a route and an Inbox → Deliveries view. It carries kinds,
  channels, addresses and reasons; never subjects or summaries.
- **The assumptions register** (migration 0056), the last named feature
  gap in Phase 6. An assumption is what the analysis takes for granted,
  and writing it down is what makes it reviewable. Open and confirmed
  statements reach the report; withdrawn and refuted ones do not.
- **Retention rules can be confirmed from the console.** The panel that
  lists unconfirmed rules offered no way to confirm one, so the only route
  was `curl`.
- **Escalation of an unacknowledged priority-1**, three registered
  notification kinds that had no producer, and a `notify_drain.py` cron
  entry.

### The compartment registry (migration 0057)

Compartments were free text, so a typo was a case nobody could see. They
are now registered, and every write site validates against the registry.

The migration refuses to run rather than silently skipping a value it
cannot register, and the decision about what to do with a legacy value
that cannot satisfy the format is stated in its docstring rather than
left to be discovered.

### Fixes worth naming

- **The purge reported bytes destroyed that were still in the bucket.**
  `EvidenceStorage.delete()` inserts a delete marker on a versioned,
  locked bucket and returns success. The purge now calls
  `delete_all_versions`, marks only rows whose objects the store confirmed
  gone, and counts exhibit ROWS in the operator-facing counter rather than
  object VERSIONS, which two docstrings had claimed it already did.
- **The evidence integrity alarm was an outbound-email amplifier.** It
  re-fired on every read of a corrupt exhibit, on a route with no rate
  limit, and each alarm then fanned out to every security officer. It is
  now idempotent while unacknowledged.
- **Strict session binding covered the HTTP path only.** A token refused
  on every request was accepted on the live event stream, where it also
  slid the idle window and kept the victim's session alive.
- **`/sources/{id}/run` returned a RED source's hostname** in its error
  string, under a module docstring certifying that route as safe.
- **`/analytics/latest` claimed `cached: true`** with no hash check, and
  the console rendered that as "unchanged since the last run", staleness
  reported as freshness, on the pane that names people.
- The collection listing endpoints filter on the caller's ceiling;
  `suppressed` and `triage_state` have writers; search reaches
  `collect.document`. The triage write is gated on the document's label
  and its source's, because the read is.

### The console

Custody verify, the delivery ledger, the readiness register, retention
confirmation, the assumptions register, and the analytics pane showing the
last completed run instead of an empty scoreboard. `/auth/me` now carries
`display_name`, so the app bar greets an analyst by name rather than with
their own UUID.

Also: `.h3`/`.h4` were scoped to the analytics pane while three other
panes used them and got the browser's default `<h3>`; `.pane-title` had
been in the Inbox markup since it was written and was never defined; the
keyboard sheet ran past the bottom of a short viewport with its close
button on the far side; and the two widest tables now scroll inside their
own box.

### Documentation is now checked against the tree

`test_doc_invariants.py` proved that a cited *document* exists. The
roadmap is written mostly in three other currencies (source files, test
names and endpoints) and none of them were checked. Three new tests
close that: a cited module must be in the tree, a cited test must be
defined, and a cited endpoint must be routed.

The scoreboard's overall figure was corrected from ~95% to 92.7%. It had
never been recomputed after the per-phase numbers were revised downward,
so the summary and the table it summarised disagreed, which is the same
defect the document catalogues everywhere else.

### Known

The suite is not order-independent on a REUSED database:
`test_an_expired_dead_letter_can_be_purged_even_if_it_predates_0040`
passes alone and fails when an earlier test in the same session has left a
case with expired retention and unpurged evidence. It is a property of the
fixture estate, not of the purge, and a fresh database does not show it.

## Alpha 3: 2026-09-01

Interface release. **Still not audited, and still not lawful to operate
against real material until the five blocking items in
[docs/16](../docs/16-legal-and-external.md) are settled by somebody
outside this codebase.** Nothing in this release touches those.

### The console was reskinned

Elevation now comes from LIGHT rather than paint: a translucent wash and a
hairline over a gradient ground, instead of a ladder of five opaque greys.
That is what makes a panel read as lit rather than filled, and it is the
single largest visual change here. It brings a radius scale (4/8/12/14 and
a pill), a 4px spacing scale, a shadow scale and motion tokens, the first
cut had six ad-hoc radii between 3px and 10px, which is what made the
console look a decade older than it is.

The seventeen rail tabs moved from Unicode dingbats to inline SVG. That is
not only cosmetic: a dingbat is drawn by whichever font the OS falls back
to, so the rail's weight and optical size varied per machine, and two of
the seventeen (U+2751, U+25E9) have no coverage in the stock Windows UI
font and rendered as empty boxes.

### The theme contract is now enforced

`theme.css` has claimed since it was written that app.css names no colour
outside the token file. That claim was false, and the test it named as the
enforcer did not exist. Nine raw `rgba()` literals had accumulated in
app.css and twelve hard-coded hexes in app.js, four of them duplicating
tokens the theme already defined and nothing used.

The app.js case was the worse one. The canvas painters read a token and
fell back to a literal (`PAINT.surface2 || '#2D2030'`) and `cssVar()`
returns `''` for a token that does not resolve. `''` is falsy, so a renamed
token did not fail: it silently painted the PREVIOUS theme onto the canvas
while the DOM around it painted the new one.

`test_theme_contract.py` (18 tests) now checks all of it: no colour literal
in either file, no undefined token, no dead token, no radius outside the
scale, and the colour rules the theme file declares load-bearing.

### Contrast fixes, several of them real defects

- `--text-tertiary` carried real labels at 3.79:1 for the whole of the
  first cut. It is 4.52:1 and clears AA for the first time.
- `--danger` sat at 3.70:1 while being the colour that says a thing will be
  destroyed. Now 4.99:1.
- `.chip.conf-LOW` and `.st-none` set a dim colour AND inherited a dim
  opacity, compositing to 1.83:1, a confidence label nobody could read.
  Confidence stays encoded as opacity; the floor moved to 0.58.
- Form controls had no boundary: `--hairline` measures 1.48:1 against the
  card a field sits on. A dedicated `--field-edge` measures 3.30:1. This
  cannot be fixed with a fill. The ground is near-black, so a recessed
  field reaches only 1.18:1 however dark it goes.
- `--artefact-finance` and `--alert` were 4.4 degrees apart, which violated
  the theme file's own stated rule that the two must not converge. Now 17.0.
- The seven node hues are held apart by CIEDE2000 rather than by eye: the
  closest pair went from 12.0 to 15.8.

### Responsive

Three media queries became ten, including the first height-axis rules in
the file. Every real failure in this layout was a height failure: the rail
is a column of seventeen tabs needing ~900px, and it used to `overflow:
hidden` and simply amputate the last few with no way to reach them.

The app bar no longer wraps its buttons onto two lines, and no longer
scrolls the page sideways. `#hdr-user` was 326px of that bar (a third of
it) because `/auth/me` returned a user_id and nothing else, so the pill
could only render a raw UUID. (`/auth/me` carries `display_name` and
`email` as of Alpha 4, and the bar now renders the name.)

### Also

- The read-path Postgres tests are gated on `DATABASE_URL` like every other
  `*_pg.py` file. Without one they errored in fixture setup rather than
  skipping, so a healthy local run ended `902 passed, 890 skipped, 11
  errors`.
- All sixteen console screenshots re-shot on the new UI, against the
  documented `OP-SHOWCASE-26` showcase seed. The **Analysis** pane is no
  longer the empty "Run analysis" prompt it had been in every previous
  release: brokerage, Burt constraint, effective size, communities and the
  key-player cut set are computed and shown.

## Alpha 2: 2026-08-25

Second packaged release. **Still not audited, and still not lawful to
operate against real material until the five blocking items in
[docs/16](../docs/16-legal-and-external.md) are settled by somebody
outside this codebase.** No amount of code closes them.

### New

- **Analyst administration.** Creating an account used to require a shell
  on the server with `DATABASE_URL` and the TOTP key exported. There is
  now an **Admin** pane: create analysts with one-shot credentials, grant
  and revoke global roles, set clearance, deactivate (which revokes their
  sessions), unlock after failed logins, and re-issue a TOTP secret for
  the analyst whose phone is gone. Behind `user.manage`, SYS_ADMIN only,
  step-up enforced.
- **First-run setup in the browser.** A fresh install offers setup on the
  sign-in screen instead of demanding the CLI. The door is gated on the
  user table being empty, under an advisory lock, and closes permanently
  at the first account.
- **Phase 4's read path.** `collect.document` and `collect.watch_hit`
  were written by the collector from the day the phase landed and read by
  nothing. A watch could fire four hundred times and an analyst saw the
  integer. Feeds -> **Collected** now lists documents and watch hits,
  with acknowledgement.
- **Dual-control approvals have a surface.** Before this, a case with
  dual control on merges could not be merged from the browser at all: the
  endpoint demanded an `approval_request_id` nothing could produce.
- **Metric-history trend chart** (Analysis -> Trend), the last UI gap in
  Phase 3.
- **New theme.** Wine-shifted "Mulberry Nocturne" palette; tokens live in
  `theme.css` so a reskin never touches structure.
- `start.cmd` for double-click launching on Windows.

### Fixed

- **Every phase has now had an adversarial review** -- Phase 6 was the
  last. Nine findings, all closed, including `unmerge` writing recorded
  endpoints over an edge a later live merge owned (reversal is now
  LIFO-enforced), a dry-run purge that reported all-zero counts so the
  preview could not distinguish "nothing due" from "twelve exhibits about
  to be destroyed", and a refused approval whose audit row was rolled
  back by the transaction that refused it.
- **The audit chain had no anchor.** A forged "first row" passed every
  check and left `/audit/verify` answering INTACT. Now reported.
- **Break-glass no longer claims an elevation it does not perform.** It
  never raised effective clearance; the claim is withdrawn rather than
  implemented, because an analyst who believes it worked stops looking
  for another way in during the incident it exists for.
- Four analyst panes that reported a failure as a fact about the case,
  including co-participation rendering "undefined -- undefined" on every
  row under a fully green suite.

### Still not in it

- The five blocking legal items (docs/16 L1-L5). Sample handling and
  stealer-log data must not be switched on until they are settled.
- No security audit and no penetration test.
- XenForo / MyBB / Telegram collection adapters; document embeddings; a
  collection scheduler process.
- Fuzzy hashing, YARA and sandbox detonation. Each absence is recorded on
  the sample row with its reason.
- Deferred hardening: session IP/UA binding, RLS under a non-owner
  database role, DNS-rebinding-proof SSRF protection, login timing
  equalisation.
- WebAuthn -- deliberate; TOTP is the floor.
- CONCOR; the assumptions register.

### Verification at release

| | |
|---|---|
| Tests | 1891 passing, 0 failing, 0 skipped, across `apps/api/tests` and `packages/ontology` |
| Lint | ruff clean |
| Database | Alembic head 0055 |
| Adversarial passes | 9, each of which found a real defect |


## Alpha 1: 2026-07-26

First packaged release. **Not audited; not lawful to operate against real
material until the four items in [README.md](README.md) are settled.**

### What is in it

Every phase has a service, a test suite, an HTTP API gated by the
five-part access check, an analyst pane, and at least one adversarial
review.

- **Graph and assertions**, nothing is written without a graded source.
- **Sociogram** with projections, ego networks, shortest path, and an
  as-of timeline. **Live**: another analyst's changes now arrive without a
  refresh.
- **Analytics**, centralities, Leiden communities, Burt constraint, cut
  vertices, key-player sets, signed balance. Computed over the projection
  and labelled as such.
- **Collection**, adapter interface, scheduler, persona vault, watch
  matching, and a proposal review gate.
- **Notification and egress**: one classification gate on every outbound
  path, quiet hours, digests, HMAC webhooks, and a delivery ledger that
  records refusals with their reason.
- **Tradecraft**, reversible entity merge, dual control, ACH, redacted
  report builder, retention and purge, break-glass with mandatory review.
- **Comms**, durable-identifier normalisation across 15 platforms,
  contact-block parsing, PGP verification with three outcome classes, and
  co-participation into the sociogram.
- **Samples**, separate-origin download, encrypted at rest, quarantine to
  RE queue, static triage with recorded gaps, and a detonation
  authorisation record.
- **Ingest**. Write-only keys, raw-before-parse, category classification,
  triage scoring, near-duplicate folding, and a dead-letter queue.

### Notable in this release

- **Live change push.** Postgres `LISTEN`/`NOTIFY`, statement-level, so a
  400-row write wakes a client once. The socket carries **no case
  content**. It is a hint to refetch through the gated endpoints, which
  is why it needs no filtering logic of its own.
- **The Lab pane.** Invariant 10 as a screen: metadata renders, bytes
  never do. No preview, no hex view, no `innerHTML` and no iframe anywhere
  in it.
- **Detonation / VM panel.** Records an authorisation and submits nothing,
  with the consequence of each exposure level written next to it.
- **Deceptive-character defence.** Bidi overrides and zero-width
  characters are substituted before reaching the DOM, at the data
  boundary rather than at each of the two dozen sites a label is drawn.
- **A `?` keyboard map** and a request indicator covering every fetch.

### Known limitations

Documented rather than hidden. `docs/17-flagged-for-review.md` is the
full list.

- No third-party security audit.
- WebAuthn is not implemented; authentication is password + TOTP.
- Fuzzy hashing (imphash, ssdeep, TLSH), YARA matching and sandbox
  detonation are **not built**. Each absence is recorded on the sample row
  with its reason, a NULL imphash reads as "no imports", a recorded gap
  reads as "nobody looked".
- Deferred hardening: session IP/UA binding, RLS under a non-owner
  database role, DNS-rebinding-proof SSRF protection, login timing
  equalisation.
- Phase 6's adversarial review is partial: ACH has had one; merges,
  retention, approvals and break-glass have not.
- No collection scheduler process, collection runs when invoked.
- Metric history is not charted, and CONCOR is not implemented.

### Verification at release

| | |
|---|---|
| Tests | 1206 passing, 0 skipped, across `apps/api/tests` and `packages/ontology` |
| Lint | ruff clean |
| Database | Alembic head 0045 |
| Adversarial passes | 7, each of which found a real defect |
