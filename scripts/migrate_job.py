"""The production migration job: refuse what must not migrate, then run
`alembic upgrade head` as the schema owner (docs/17 F52, 2026-10-02).

    python scripts/migrate_job.py

infra/production/compose.yml runs this as the `migrate` service, which
reads migrate.env and nothing else. It is not for a development stack,
where `alembic upgrade head` is run directly against .env.local.

## Why a script and not the two lines of shell it replaces

Until 2026-10-02 the service's shell copied NOCTORNAL_MIGRATION_DATABASE_URL
into DATABASE_URL and exec'd Alembic, and the owner's DSN sat in
secrets.env, where the API's boot check refused a published owner password
for it. F52 moved the DSN into a file only this job reads, so that refusal
has to be made here or nobody makes it. And on a host whose secrets were
not moved yet, an empty variable would have reached Alembic as an empty
DATABASE_URL, whose message is about .env.local and a laptop's shell. The
refusals are `config.migration_job_problems`, one line each, naming the fix
and never a value. The published-credential one is the helper every other
job makes (`config.refuse_unsafe_job_environment`, infra-12), with the
owner half switched off because this job is the one that holds the owner's
DSN. Any refusal exits 1, which keeps every service that waits on this job
from starting. Alembic's own environment (db/migrations/env.py) makes the
same published-credential refusal once more when it starts, so a bare
`alembic` is held to it too; that one exits 2, as every other job's does.

When there is nothing to refuse, DATABASE_URL is replaced in this
process's environment with the owner's DSN (Alembic and the application
read the same variable, and must not be the same role) and Alembic is
exec'd in this process's place, so its exit status is the job's.
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402
from noctornal_api.config import MIGRATION_DSN_ENV, migration_job_problems  # noqa: E402


def main(env=None, *, execvpe=os.execvpe, err=sys.stderr) -> int:
    env = dict(os.environ if env is None else env)
    dsn = env.get(MIGRATION_DSN_ENV, "").strip()
    problems = migration_job_problems(env)
    if not problems and not dsn:
        # Outside production the rules above are off, and there is still
        # nothing to migrate with.
        problems = [f"migrate: {MIGRATION_DSN_ENV} is not set. This job belongs to "
                    f"the production compose file; a development stack runs "
                    f"alembic upgrade head itself."]
    if problems:
        for problem in problems:
            print(problem, file=err)
        return 1
    env["DATABASE_URL"] = dsn
    execvpe("alembic", ["alembic", "upgrade", "head"], env)
    return 0  # reached only when execvpe is replaced, as the tests do


if __name__ == "__main__":
    # Every script here reads .env.local the one way (scripts/_env.py). In
    # the container there is none (.dockerignore keeps it out of the
    # image), and it never overrides a variable already set, so on a host
    # it can add a DATABASE_URL this job then replaces and never an owner
    # DSN: .env.local does not carry one.
    load_env_local()
    sys.exit(main())
