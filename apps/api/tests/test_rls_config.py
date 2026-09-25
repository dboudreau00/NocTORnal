"""Who may hold the system role's DSN, refused at boot (S1, 2026-09-25).

`NOCTORNAL_WORKER_DATABASE_URL` connects as the role that bypasses row
security. Every production process but the sample origin needs it (the
work that must see every row runs on it); the sample origin, which serves
hostile bytes, must never hold it; it must not be the role DATABASE_URL
names; the initdb-only password belongs to the database alone; and the
development switch that makes the suite assume the runtime roles never
reaches production. Empty is unset everywhere: the sample origin's compose
value is "".
"""
from __future__ import annotations

import pytest

from noctornal_api.config import verify_environment
from test_config_boot import _only, _production

WORKER = "NOCTORNAL_WORKER_DATABASE_URL"


def test_a_production_process_without_the_worker_dsn_is_refused_by_name():
    env = _production()
    del env[WORKER]
    problem = _only(verify_environment(env), WORKER)
    assert "noctornal_worker" in problem and problem.endswith(".")


@pytest.mark.parametrize("value", ["", "   "])
def test_an_empty_worker_dsn_is_unset(value):
    env = _production()
    env[WORKER] = value
    _only(verify_environment(env), WORKER)


def _sample_origin(env: dict) -> dict:
    env = dict(env)
    env["NOCTORNAL_SAMPLE_ORIGIN"] = "https://samples.example.gov"
    env["NOCTORNAL_PUBLIC_ORIGIN"] = "https://samples.example.gov"
    return env


def test_the_sample_origin_is_refused_the_worker_dsn_and_fine_without_it():
    from noctornal_api.samples import origin_split
    from noctornal_api.config import _borrowing

    env = _sample_origin(_production())
    with _borrowing(env, "NOCTORNAL_SAMPLE_ORIGIN", "NOCTORNAL_BASE_URL",
                    "NOCTORNAL_PUBLIC_ORIGIN"):
        assert origin_split().serves_here, "the fixture must describe the sample origin"
    assert any("sample origin" in p and WORKER in p for p in verify_environment(env))
    env[WORKER] = ""  # compose's value there
    assert not any(WORKER in p for p in verify_environment(env))


def test_the_worker_dsn_may_not_name_the_request_role():
    env = _production()
    env[WORKER] = env["DATABASE_URL"].replace("Xk9pQ", "Other7x")
    problem = _only(verify_environment(env), WORKER)
    assert "same role" in problem
    assert "Xk9pQ" not in problem and "Other7x" not in problem


@pytest.mark.parametrize("name", ["NOCTORNAL_WORKER_DB_PASSWORD",
                                  "NOCTORNAL_TEST_ASSUME_ROLE"])
def test_the_initdb_password_and_the_test_switch_are_refused_in_production(name):
    env = _production()
    env[name] = "Zq8wLm3vT"
    problem = _only(verify_environment(env), name)
    assert "Zq8wLm3vT" not in problem


def test_none_of_it_applies_outside_production():
    env = _production()
    env["NOCTORNAL_ENV"] = "development"
    del env[WORKER]
    env["NOCTORNAL_TEST_ASSUME_ROLE"] = "1"
    assert verify_environment(env) == []
