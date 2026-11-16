"""docs/17, "no statement timeout".

Without a bound on the statements of a request connection, a request nobody is waiting for any more keeps
running (ten register queries were seen stacked, the oldest ten minutes old). A request connection is
opened with a `statement_timeout`, `NOCTORNAL_REQUEST_STATEMENT_TIMEOUT` seconds (120 by default), and a
request that hits it answers a 504 problem with a reference, never a 500 and a trace.

What these hold:

- the limit is on REQUEST connections and on no other: a system connection, a job and a migration are
  opened without it;
- the setting is a whole number of seconds from 5 to 3600, anything else reads as the default, and nothing
  switches the limit off;
- an operator's own `statement_timeout` in DATABASE_URL is not loosened by the default, and their explicit
  setting wins over it;
- a `statement_timeout` in DATABASE_URL is held to the same 5 to 3600 seconds and the bound always goes
  last, so the DSN cannot switch it off, and production refuses a DSN whose options try (the independent review
  TRANSPORT-04);
- a real overrun is a 504 problem whichever way the router meets it: raised as it is, wrapped by a service
  error, or turned into a `Problem` through `safe_detail`; and the answer names nothing of the statement.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import time

import psycopg
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from noctornal_api import db

needs_db = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                              reason="needs a migrated database")


@pytest.fixture(autouse=True)
def _no_inherited_setting(monkeypatch):
    monkeypatch.delenv(db.REQUEST_STATEMENT_TIMEOUT_ENV, raising=False)


@pytest.mark.parametrize("raw, expected", [
    (None, (120, False)), ("", (120, False)), ("90", (90, True)), (" 45 ", (45, True)),
    ("5", (5, True)), ("3600", (3600, True)),
    ("0", (120, False)), ("4", (120, False)), ("3601", (120, False)),
    ("-5", (120, False)), ("1.5", (120, False)), ("30s", (120, False)),
    ("off", (120, False)), ("none", (120, False)),
])
def test_the_setting_is_a_whole_number_of_seconds_and_nothing_switches_it_off(
        raw, expected, monkeypatch):
    if raw is not None:
        monkeypatch.setenv(db.REQUEST_STATEMENT_TIMEOUT_ENV, raw)
    assert db.request_statement_timeout() == expected


def test_a_request_connection_is_opened_with_the_limit_and_the_others_without():
    url = "postgresql://u@h:5432/d"
    assert db.session_options(url) == "-c jit=off"
    assert db.session_options(url, for_request=True) == "-c jit=off -c statement_timeout=120000"


def test_an_operators_statement_timeout_in_the_dsn_is_not_loosened_by_the_default(monkeypatch):
    """The latest wins in the server's options, and the bound goes last: the operator's own value
    when it is within the limits, and their explicit setting over it."""
    named = "postgresql://u@h:5432/d?options=-c%20statement_timeout%3D7s"
    assert db.session_options(named, for_request=True) == \
        "-c statement_timeout=7s -c jit=off -c statement_timeout=7000"
    monkeypatch.setenv(db.REQUEST_STATEMENT_TIMEOUT_ENV, "30")
    assert db.session_options(named, for_request=True) == \
        "-c statement_timeout=7s -c jit=off -c statement_timeout=30000"
    assert db.session_options(named) == "-c statement_timeout=7s -c jit=off", \
        "a connection that is not a request's is opened as it was"


def _with_options(options: str) -> str:
    from urllib.parse import quote
    return "postgresql://u@h:5432/d?options=" + quote(options, safe="")


@pytest.mark.parametrize("options, bound_ms", [
    ("-c statement_timeout=0", 3_600_000),
    ("-c statement_timeout=0ms", 3_600_000),
    ("-c statement_timeout=0x0", 3_600_000),
    ("-cstatement_timeout=0", 3_600_000),
    ("--statement-timeout=0", 3_600_000),
    ("-c STATEMENT_TIMEOUT=0", 3_600_000),
    ("-c statement_timeout=2h", 3_600_000),
    ("-c statement_timeout=86400000", 3_600_000),
    ("-c statement_timeout=1s", 5_000),
    ("-c statement_timeout=1500", 5_000),
    ("-c statement_timeout=90s", 90_000),
    ("-c statement_timeout=5\\ min", 300_000),
    ("-c statement_timeout=7s -c statement_timeout=0", 3_600_000),
    ("-c statement_timeout=nonsense", 120_000),
    ("-c search_path=public", 120_000),
])
def test_the_dsns_statement_timeout_is_held_to_the_limits_and_the_bound_goes_last(options, bound_ms):
    """the independent review TRANSPORT-04: the default went BEFORE the DSN's options, so `statement_timeout=0` there
    switched the bound off for every request connection, while the setting meant to be the one control
    could not. Each spelling the server reads is held to 5 to 3600 seconds, one that is off is the
    longest bound, one that cannot be read is the default, and the bound is the last word on the line,
    which the server applies."""
    built = db.session_options(_with_options(options), for_request=True)
    assert built.endswith(f" -c statement_timeout={bound_ms}"), built
    assert db.request_statement_timeout_ms(_with_options(options)) == bound_ms


@pytest.mark.parametrize("options, refused", [
    ("-c statement_timeout=0", "switch statement_timeout off"),
    ("--statement-timeout=0s", "switch statement_timeout off"),
    ("-c statement_timeout=nonsense", "not a bound this can read"),
    ("-c statement_timeout=-5", "not a bound this can read"),
    ("-c statement_timeout=7s", None),
    ("-c search_path=public", None),
])
def test_production_refuses_a_dsn_whose_options_switch_the_timeout_off(options, refused):
    from test_config_boot import _production

    from noctornal_api import config

    from urllib.parse import quote

    # The compose shape, `postgresql+psycopg://` and its TLS query, so the reader is the one a
    # deployment's DSN meets.
    env = _production()
    env["DATABASE_URL"] += "&options=" + quote(options, safe="")
    assert env["DATABASE_URL"].startswith("postgresql+psycopg://")
    said = [p for p in config.verify_environment(env) if "statement_timeout" in p]
    if refused is None:
        assert said == []
    else:
        assert len(said) == 1, said
        assert said[0].startswith("DATABASE_URL's options ") and refused in said[0]
        assert db.REQUEST_STATEMENT_TIMEOUT_ENV in said[0]
    development = {**env, "NOCTORNAL_ENV": "development"}
    assert config.verify_environment(development) == []
    assert config.request_timeout_problems(development) == config.request_timeout_problems(env), \
        "pure and mode-blind: verify_environment applies it in production"


@needs_db
def test_a_request_connection_runs_with_the_limit(monkeypatch):
    conn = db.connect_request()
    try:
        assert conn.execute("SHOW statement_timeout").fetchone()[0] == "2min"
    finally:
        conn.close()
    monkeypatch.setenv(db.REQUEST_STATEMENT_TIMEOUT_ENV, "45")
    conn = db.connect_request()
    try:
        assert conn.execute("SHOW statement_timeout").fetchone()[0] == "45s"
    finally:
        conn.close()


@needs_db
def test_a_dsn_that_switches_the_timeout_off_still_runs_bounded(monkeypatch):
    """Against the server: before the bound went last, this connection ran with `0`."""
    url = db.dsn()
    sep = "&" if "?" in url else "?"
    monkeypatch.setenv("DATABASE_URL", url + sep + "options=-c%20statement_timeout%3D0")
    conn = db.connect_request()
    try:
        assert conn.execute("SHOW statement_timeout").fetchone()[0] == "1h"
    finally:
        conn.close()


@needs_db
def test_no_other_connection_is_bounded(monkeypatch):
    """The connection helper, a system connection and the way a job opens
    its own: whatever the server's default is, they have it."""
    monkeypatch.setenv(db.REQUEST_STATEMENT_TIMEOUT_ENV, "30")
    plain = psycopg.connect(db.dsn(), autocommit=True)
    try:
        server_default = plain.execute("SHOW statement_timeout").fetchone()[0]
    finally:
        plain.close()
    opened = [db.connect(), db.connect_system(db.SystemPurpose.SCRIPT)]
    try:
        for conn in opened:
            assert conn.execute("SHOW statement_timeout").fetchone()[0] == server_default
    finally:
        for conn in opened:
            conn.close()


@needs_db
def test_the_dsns_own_limit_stays_on_a_request_connection(monkeypatch):
    url = db.dsn()
    sep = "&" if "?" in url else "?"
    monkeypatch.setenv("DATABASE_URL", url + sep + "options=-c%20statement_timeout%3D7s")
    conn = db.connect_request()
    try:
        assert conn.execute("SHOW statement_timeout").fetchone()[0] == "7s"
    finally:
        conn.close()
    monkeypatch.setenv(db.REQUEST_STATEMENT_TIMEOUT_ENV, "30")
    conn = db.connect_request()
    try:
        assert conn.execute("SHOW statement_timeout").fetchone()[0] == "30s"
    finally:
        conn.close()


# --- a real overrun, through the error handlers ------------------------------------------

def _app():
    from noctornal_api.graph import GraphWriteError
    from noctornal_api.http.deps import get_conn
    from noctornal_api.http.errors import Problem, install_error_handlers, safe_detail

    app = FastAPI()
    install_error_handlers(app)

    def overrun(conn):
        conn.execute("SET statement_timeout = '150ms'")
        conn.execute("SELECT pg_sleep(30), 'secret-column-value'")

    @app.get("/plain")
    def plain(conn: psycopg.Connection = Depends(get_conn)):
        overrun(conn)

    @app.get("/wrapped")
    def wrapped(conn: psycopg.Connection = Depends(get_conn)):
        try:
            overrun(conn)
        except psycopg.Error as exc:
            raise GraphWriteError(str(exc)) from exc

    @app.get("/through-safe-detail")
    def through_safe_detail(conn: psycopg.Connection = Depends(get_conn)):
        from noctornal_api.proposals import ProposalError
        try:
            overrun(conn)
        except psycopg.Error as exc:
            wrapped_error = ProposalError(str(exc))
            wrapped_error.__cause__ = exc
            raise Problem(400, "Invalid request", safe_detail(wrapped_error)) from exc

    @app.get("/other-failure")
    def other_failure(conn: psycopg.Connection = Depends(get_conn)):
        conn.execute("SELECT 1/0")

    return TestClient(app, raise_server_exceptions=False)


@needs_db
@pytest.mark.parametrize("path", ["/plain", "/wrapped", "/through-safe-detail"])
def test_a_statement_that_overran_is_a_504_problem_with_a_reference(path):
    started = time.monotonic()
    response = _app().get(path)
    assert time.monotonic() - started < 20, "the statement was not cancelled"
    assert response.status_code == 504
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["status"] == 504 and body["title"] == "Gateway timeout"
    assert body["detail"].startswith("The database did not finish within the time")
    assert "(ref " in body["detail"]
    text = response.text
    for leak in ("pg_sleep", "secret-column-value", "canceling statement", "Traceback",
                 "statement_timeout"):
        assert leak not in text, leak


@needs_db
def test_the_overrun_is_logged_against_its_reference(caplog):
    with caplog.at_level("WARNING", logger="noctornal.api"):
        response = _app().get("/plain")
    ref = response.json()["detail"].rsplit("(ref ", 1)[1].rstrip(")")
    logged = [r.getMessage() for r in caplog.records if ref in r.getMessage()]
    assert logged and "GET /plain" in logged[0]


@needs_db
def test_another_database_failure_is_still_what_it_was():
    """A division by zero is the caller's input, a 422, not a timeout."""
    response = _app().get("/other-failure")
    assert response.status_code == 422
