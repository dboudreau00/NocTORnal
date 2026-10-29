"""The production migration job: refuse what must not migrate, then run `alembic upgrade head` as
the schema owner.

    python scripts/migrate_job.py

infra/production/compose.yml runs this as the `migrate` service, which reads migrate.env and
nothing else. It is not for a development stack, where `alembic upgrade head` runs directly against
.env.local.

The owner's DSN is in a file only this job reads, so its refusals are made here or nowhere:
`config.migration_job_problems`, one line each, naming the fix and never a value. The
published-credential refusal is the one every job makes (`config.refuse_unsafe_job_environment`),
with the owner half off because this job holds the owner's DSN. Any refusal exits 1, which keeps
every service that waits on this job from starting; db/migrations/env.py repeats the
published-credential refusal (exit 2), so a bare `alembic` is held to it too.

Otherwise DATABASE_URL is replaced in this process's environment with the owner's DSN (Alembic and
the application read the same variable and must not be the same role) and Alembic is exec'd in
this process's place, so its exit status is the job's.
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
    # .env.local never overrides a variable already set and never carries an owner DSN, so at most
    # it adds a DATABASE_URL this job replaces. The image has none (.dockerignore).
    load_env_local()
    sys.exit(main())
