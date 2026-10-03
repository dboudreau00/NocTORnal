"""A production boot refuses a request DSN that names the schema owner or a
superuser (infra-4, 2026-10-03).

Row-level security does not bind the owner, and an owner may ALTER TABLE ...
DISABLE TRIGGER on the audit and custody chains, so a request connection that
carries either role switches both off for every analyst request while the
register shows a running deployment. The system connection already refused
exactly that role (`db.connect_system`); the request one accepted it, and the
only signal was a readiness row that is not blocking. These are the boot half,
which reads names from the environment. The half that reads the catalog is in
`test_g48_request_role_pg.py`.

Pure: every rule reads a dictionary, as test_config_boot.py does.
"""
from __future__ import annotations

import pytest

from noctornal_api.config import verify_environment
from test_config_boot import _only, _production

OWNER_DSN = "postgresql+psycopg://dbowner:Zq8wLm@db:5432/noctornal"


def test_a_request_dsn_naming_the_migration_dsns_role_is_refused():
    env = _production()
    env["NOCTORNAL_MIGRATION_DATABASE_URL"] = OWNER_DSN
    env["DATABASE_URL"] = OWNER_DSN.replace("Zq8wLm", "Other7x")
    problem = _only(verify_environment(env), "DATABASE_URL")
    assert "schema owner or a superuser" in problem and "noctornal_app" in problem
    assert "dbowner" not in problem and "Zq8wLm" not in problem and "Other7x" not in problem
    assert problem.endswith(".")


def test_the_refusal_says_what_to_do_when_the_least_privilege_role_does_not_exist_yet():
    """It used to say only 'point it at noctornal_app', which on a volume
    initialised without NOCTORNAL_APP_DB_PASSWORD is a role that does not
    exist, with nothing in the refusal or the README to say what then (g48
    verification, 2026-10-03)."""
    env = _production()
    env["NOCTORNAL_MIGRATION_DATABASE_URL"] = OWNER_DSN
    env["DATABASE_URL"] = OWNER_DSN
    problem = _only(verify_environment(env), "DATABASE_URL")
    assert "point it at noctornal_app" in problem
    assert "initialised without NOCTORNAL_APP_DB_PASSWORD has no such role yet" in problem
    assert "infra/production/README.md, step 2" in problem
    assert "dbowner" not in problem and "Zq8wLm" not in problem


def test_a_request_dsn_naming_postgres_user_is_refused():
    env = _production()
    env["POSTGRES_USER"] = "dbowner"
    env["DATABASE_URL"] = OWNER_DSN
    _only(verify_environment(env), "DATABASE_URL")


@pytest.mark.parametrize("role", ["noctornal", "postgres"])
def test_the_owner_and_the_cluster_superuser_by_their_usual_names_are_refused(role):
    """The migration DSN is not always in the process's environment (the
    sample origin and cron share secrets.env, but a custom deployment need
    not), so the two names this repository and Postgres itself give are
    refused on their own."""
    env = _production()
    env["DATABASE_URL"] = f"postgresql+psycopg://{role}:Xk9pQ@db:5432/noctornal"
    _only(verify_environment(env), "DATABASE_URL")


def test_the_least_privilege_role_boots():
    """The other direction, and the one that matters: the role this
    repository's own compose file names, with the owner beside it for the
    migration job, starts."""
    env = _production()
    env["NOCTORNAL_MIGRATION_DATABASE_URL"] = "postgresql+psycopg://noctornal:Zq8wLm@db:5432/noctornal"
    env["POSTGRES_USER"] = "noctornal"
    assert env["DATABASE_URL"].startswith("postgresql+psycopg://noctornal_app:")
    assert verify_environment(env) == []


def test_a_role_that_merely_starts_like_the_owner_is_not_refused():
    env = _production()
    env["NOCTORNAL_MIGRATION_DATABASE_URL"] = "postgresql+psycopg://noctornal:Zq8wLm@db:5432/noctornal"
    env["DATABASE_URL"] = "postgresql+psycopg://noctornal_runtime:Xk9pQ@db:5432/noctornal"
    assert verify_environment(env) == []


def test_none_of_it_applies_outside_production():
    env = _production()
    env["NOCTORNAL_ENV"] = "development"
    env["DATABASE_URL"] = OWNER_DSN
    env["NOCTORNAL_MIGRATION_DATABASE_URL"] = OWNER_DSN
    assert verify_environment(env) == []


def test_the_verifier_reproduction_from_the_review_is_closed():
    """scratchpad/review/verify_env_probe.py: a valid production environment
    with DATABASE_URL set to the owner DSN had 0 refusals."""
    env = _production()
    env["NOCTORNAL_MIGRATION_DATABASE_URL"] = "postgresql+psycopg://noctornal:Zq8wLm@db:5432/noctornal"
    env["DATABASE_URL"] = env["NOCTORNAL_MIGRATION_DATABASE_URL"]
    assert len(verify_environment(env)) == 1
