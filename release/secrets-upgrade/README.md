# Upgrading an existing deployment: the owner's credential and Redis

From this release (2026-10-02) the production deployment keeps the schema
owner's credential out of `secrets.env`, and its Redis runs an ACL in which
the default user is disabled and the rate limiter has a user of its own
(`docs/17` F52; the Redis isolation item of `ROADMAP-REMAINING.md`). An
existing deployment keeps its data, its passwords and its sessions. It
needs one command before `up`, and refuses to start without it.

## What stops, and what it says

| Service | Refuses because | Says |
|---|---|---|
| `migrate` | `migrate.env` is missing, so it has no owner DSN | `NOCTORNAL_MIGRATION_DATABASE_URL is not set for the migration job ...` |
| `redis` | `REDIS_URL` names this Redis (host `redis`) and does not sign in as `noctornal_limiter` | `REDIS_URL does not sign in to this Redis as noctornal_limiter with REDIS_PASSWORD ...` |

Every service that waits on `migrate` or on a healthy `redis` stays down
with them. Each sentence names the command below and none quotes a value.

A `secrets.env` that still carries the owner's lines once `migrate.env`
exists stops nothing: `compose.yml` hands every service but postgres and
the migrate job both variables empty, so neither reaches a running
process. The API, the cron jobs and the egress proxy also refuse to run
holding either, for a deployment other than this compose file. The command
below removes the lines either way.

## 1. Pull, then bring the secrets files along

```sh
git pull
sudo ./release/install.sh --production-secrets
```

With `sudo`, because the files are root's, mode 600: run as anybody else it
can read none of them, and says so in one sentence naming the file. On
Windows: `powershell -ExecutionPolicy Bypass -File .\release\install.ps1
-ProductionSecrets`, as the user who owns the files. It needs `python3` 3.8
or later on the host and no virtual environment. In `infra/production` it:

* copies every file it is about to change to `NAME.backup-UTCSTAMP`,
  mode 600 (gitignored, and kept out of the image);
* moves `POSTGRES_PASSWORD` from `secrets.env` into `postgres-init.env` and
  `NOCTORNAL_MIGRATION_DATABASE_URL` into a new `migrate.env`, leaving a
  comment where each line was, and takes the old template's comment above
  each line with it;
* keeps `REDIS_PASSWORD` when it is URL-safe (generates one when it is not)
  and rewrites `REDIS_URL` as `redis://noctornal_limiter:PASSWORD@redis:6379/0`,
  replacing the old template's comments on both lines;
* prints each change by name, and exits non-zero with a `still to do:`
  line for anything left to you.

When `postgres-init.env` already holds a DIFFERENT owner password, nothing
is written: keep the one the database was initialised with, delete the
other line, and run it again.

If a write fails part way (`stopped: cannot write NAME ...`), the files the
lines move into are written first and `secrets.env` last, and each file is
replaced whole, so `secrets.env` still holds every line it had. Fix the
cause the sentence names and run the command again: it finds the same value
in both places, which it treats as agreement, and finishes what is left.

A `REDIS_URL` naming another host is a Redis of your own, and the command
leaves it alone and says so. Give that Redis the limiter's own user
(`infra/production/README.md`, The limiter's Redis, has the rules). The
bundled `redis` service then starts with no client; `--scale redis=0` on
`up` leaves it out.

## 2. Start

```sh
docker compose -p noctornal-prod -f infra/production/compose.yml up -d --build
```

Compose recreates `redis` (its environment changed), and the limiter
signs in as its own user from the first request. No meter is lost: the
data volume is unchanged.

## 3. Confirm

Open Administration, Readiness. `redis_limiter_isolated` passes only when
the limiter signs in as `noctornal_limiter`, the default user is disabled,
and the limiter's user reads and writes `rl:` keys alone and runs its own
commands alone. Three of those commands still see past `rl:` without
reading a key: SCAN lists key names, INFO reports server statistics, and
ACL GETUSER reads users' rules, which the row says.
`app_db_role_not_owner` is unchanged and still green.

## Going back

Copy each `NAME.backup-UTCSTAMP` over its file and check out the previous
release, together: this release's compose file refuses the old layout,
and the old one does not read `migrate.env`. `infra/production/README.md`,
Upgrading, has the commands. Nothing in the database changes in either
direction.
