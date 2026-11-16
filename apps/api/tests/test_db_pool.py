"""docs/17, "a connection for every request": the pool's settings and its construction.

What these hold, with no database:

- the pool is on in production and off everywhere else unless `NOCTORNAL_DB_POOL` says `on` or `off`,
  and a misspelt value is the default, never a third mode;
- the size and the wait are whole numbers in their ranges, anything else reads as the default, so a
  typo bounds the pool rather than freeing it, and nothing makes it unbounded;
- a pooled connection is opened as `db.connect_request` opens one (autocommit, the connect timeout and
  the request connection's options, its statement timeout included), checked as it goes out, reset as it
  comes back, and replaced after its lifetime;
- a request the pool has no connection for is a 503 problem with `Retry-After`, never a 500;
- `deps.get_conn` is the one door into the pool, the live channel and the side connections stay
  unpooled, and no route closes the connection it was given.

`test_db_pool_pg.py` holds what the reset does to a real connection.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from psycopg_pool import ConnectionPool, PoolClosed, PoolTimeout, TooManyRequests

from noctornal_api import db, db_pool

_SETTINGS = (db_pool.POOL_ENV, db_pool.POOL_MIN_ENV, db_pool.POOL_MAX_ENV,
             db_pool.POOL_TIMEOUT_ENV)


@pytest.fixture(autouse=True)
def _no_inherited_settings(monkeypatch):
    for name in (*_SETTINGS, "NOCTORNAL_ENV", db.REQUEST_STATEMENT_TIMEOUT_ENV,
                 "NOCTORNAL_DB_CONNECT_TIMEOUT"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("mode, raw, expected", [
    ("production", None, True), ("development", None, False), (None, None, False),
    ("production", "off", False), ("production", " OFF ", False),
    ("development", "on", True), (None, " On ", True),
    ("production", "", True), ("development", "", False),
    ("production", "yes", True), ("development", "yes", False),
    ("production", "0", True), ("development", "1", False),
])
def test_the_pool_is_on_in_production_and_off_elsewhere_unless_told(mode, raw, expected,
                                                                      monkeypatch):
    if mode is not None:
        monkeypatch.setenv("NOCTORNAL_ENV", mode)
    if raw is not None:
        monkeypatch.setenv(db_pool.POOL_ENV, raw)
    assert db_pool.pool_enabled() is expected


def test_the_pool_defaults_to_ten_connections_and_a_ten_second_wait():
    settings = db_pool.pool_settings()
    assert (settings.min_size, settings.max_size, settings.timeout) == (1, 10, 10)
    assert settings.max_waiting == 22, "a fifth of the 40 threadpool tokens and the 10 holders stay free"


@pytest.mark.parametrize("name, raw, field, expected", [
    (db_pool.POOL_MAX_ENV, "25", "max_size", 25),
    (db_pool.POOL_MAX_ENV, " 1 ", "max_size", 1),
    (db_pool.POOL_MAX_ENV, "50", "max_size", 50),
    (db_pool.POOL_MAX_ENV, "0", "max_size", 10),
    (db_pool.POOL_MAX_ENV, "51", "max_size", 10),
    (db_pool.POOL_MAX_ENV, "-1", "max_size", 10),
    (db_pool.POOL_MAX_ENV, "unlimited", "max_size", 10),
    (db_pool.POOL_MAX_ENV, "2.5", "max_size", 10),
    (db_pool.POOL_MIN_ENV, "0", "min_size", 0),
    (db_pool.POOL_MIN_ENV, "4", "min_size", 4),
    (db_pool.POOL_MIN_ENV, "-1", "min_size", 1),
    (db_pool.POOL_MIN_ENV, "many", "min_size", 1),
    (db_pool.POOL_TIMEOUT_ENV, "1", "timeout", 1),
    (db_pool.POOL_TIMEOUT_ENV, "60", "timeout", 60),
    (db_pool.POOL_TIMEOUT_ENV, "0", "timeout", 10),
    (db_pool.POOL_TIMEOUT_ENV, "61", "timeout", 10),
    (db_pool.POOL_TIMEOUT_ENV, "10s", "timeout", 10),
    (db_pool.POOL_TIMEOUT_ENV, "none", "timeout", 10),
])
def test_invalid_pool_settings_fall_back_to_the_defaults_and_never_unbound(
        name, raw, field, expected, monkeypatch):
    monkeypatch.setenv(name, raw)
    assert getattr(db_pool.pool_settings(), field) == expected


@pytest.mark.parametrize("size, expected", [(1, 4), (5, 20), (6, 24), (10, 22), (20, 12),
                                            (31, 1), (50, 1)])
def test_waiters_never_fill_the_threadpool_the_holders_need(size, expected):
    """A waiter blocks a threadpool token in `getconn`; a connection's holder needs one to run its
    handler and give the connection back. Waiters plus holders must leave a fifth of the tokens
    free, and 0 is never returned, which psycopg_pool reads as no limit."""
    waiting = db_pool.PoolSettings(1, size, 10).max_waiting
    assert waiting == expected
    assert waiting >= 1
    assert waiting == 1 or waiting + size <= db_pool.THREADPOOL_TOKENS * 4 // 5


def test_a_minimum_above_the_maximum_is_held_to_the_maximum(monkeypatch):
    monkeypatch.setenv(db_pool.POOL_MIN_ENV, "30")
    monkeypatch.setenv(db_pool.POOL_MAX_ENV, "5")
    settings = db_pool.pool_settings()
    assert (settings.min_size, settings.max_size, settings.max_waiting) == (5, 5, 20)


def test_a_pooled_connection_is_opened_as_connect_request_opens_one(monkeypatch):
    monkeypatch.setenv(db.REQUEST_STATEMENT_TIMEOUT_ENV, "45")
    monkeypatch.setenv("NOCTORNAL_DB_CONNECT_TIMEOUT", "7")
    url = "postgresql://u@h:5432/d"
    options = db.session_options(url, for_request=True)
    settings = db_pool.PoolSettings(2, 6, 3)
    pool = db_pool._build(url, options, False, settings)
    assert isinstance(pool, ConnectionPool)
    assert pool.closed, "built, never opened: the registry opens it"
    assert pool.kwargs == {"autocommit": True, "connect_timeout": 7, "options": options,
                           "prepare_threshold": None}
    assert "statement_timeout=45000" in pool.kwargs["options"]
    assert "jit=off" in pool.kwargs["options"]
    assert (pool.min_size, pool.max_size, pool.timeout, pool.max_waiting) == (2, 6, 3, 24)
    assert pool.max_lifetime == db_pool.MAX_LIFETIME_SECONDS == 1800
    assert pool.max_idle == db_pool.MAX_IDLE_SECONDS == 300
    assert pool.name == db_pool.POOL_NAME
    assert pool._check is ConnectionPool.check_connection
    assert pool._configure is not None and pool._reset is not None


def test_the_registry_keys_a_pool_by_everything_its_connections_depend_on(monkeypatch):
    """A test or an operator that changes the DSN, the options, the role mode, the connect timeout
    or the size gets a pool of its own, never one built for the other; and the key is a digest,
    because the DSN carries the password."""
    url = "postgresql://u:placeholder@h:5432/d"
    base = db_pool._key(url, "-c jit=off", False, db_pool.PoolSettings(1, 10, 10))
    assert "placeholder" not in base and len(base) == 64
    assert base != db_pool._key(url + "x", "-c jit=off", False, db_pool.PoolSettings(1, 10, 10))
    assert base != db_pool._key(url, "-c jit=on", False, db_pool.PoolSettings(1, 10, 10))
    assert base != db_pool._key(url, "-c jit=off", True, db_pool.PoolSettings(1, 10, 10))
    assert base != db_pool._key(url, "-c jit=off", False, db_pool.PoolSettings(1, 9, 10))
    monkeypatch.setenv("NOCTORNAL_DB_CONNECT_TIMEOUT", "3")
    assert base != db_pool._key(url, "-c jit=off", False, db_pool.PoolSettings(1, 10, 10))


@pytest.mark.parametrize("error", [PoolTimeout, TooManyRequests, PoolClosed],
                         ids=lambda e: e.__name__)
def test_pool_exhaustion_answers_503_with_retry_after_and_problem_json(error):
    """No connection free in time, too many waiting, or a pool closed by a shutdown: a 503 the
    caller can retry, with a reference, never a 500 and never the pool's own text."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from noctornal_api.http.errors import POOL_UNAVAILABLE_DETAIL, install_error_handlers

    app = FastAPI()
    install_error_handlers(app)

    @app.get("/held")
    def held():
        raise error(f"couldn't get a connection from {db_pool.POOL_NAME!r} after 10.00 sec")

    r = TestClient(app, raise_server_exceptions=False).get("/held")
    assert r.status_code == 503, r.text
    assert r.headers["content-type"] == "application/problem+json"
    assert r.headers["retry-after"] == "1"
    body = r.json()
    assert body["title"] == "Service unavailable" and body["status"] == 503
    assert body["detail"].startswith(POOL_UNAVAILABLE_DETAIL + " (ref ")
    assert db_pool.POOL_NAME not in r.text and "get a connection" not in r.text


def test_db_imports_nothing_from_the_pool():
    """`db` stays the unpooled helper: the scripts, the jobs and the migrations import it, and none
    of them may come to hold a pool."""
    source = Path(db.__file__).read_text(encoding="utf-8")
    assert "db_pool" not in source
    assert "psycopg_pool" not in source


# --- what is pooled and what is not, read from the source ---------------------------------------

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "apps" / "api" / "src" / "noctornal_api"


def _sources():
    for root in (SRC, ROOT / "scripts"):
        for path in sorted(root.rglob("*.py")):
            yield path.relative_to(SRC if root == SRC else ROOT).as_posix(), \
                path.read_text(encoding="utf-8")


def _code_names(text: str) -> set[str]:
    """Every name the code uses, imports included, and nothing a comment or docstring says."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.ImportFrom):
            names.update((node.module or "").split("."))
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.update(alias.name.split("."))
    return names


def test_only_deps_get_conn_takes_a_pooled_connection():
    """One door into the pool: `deps.get_conn`. A second caller could hold a pooled connection
    while its request holds another, and a pool every request waits on twice deadlocks; the
    application's shutdown is the one other module that names the pool, to close it."""
    used = {rel: _code_names(text) for rel, text in _sources() if rel != "db_pool.py"}
    assert {rel for rel, names in used.items() if "request_connection" in names} == \
        {"http/deps.py"}
    assert {rel for rel, names in used.items() if "db_pool" in names} == \
        {"http/deps.py", "http/app.py"}
    assert re.search(r"^from noctornal_api\.db_pool import request_connection$",
                     (SRC / "http" / "deps.py").read_text(encoding="utf-8"), re.M)
    deps = (SRC / "http" / "deps.py").read_text(encoding="utf-8")
    body = deps[deps.index("def get_conn("):deps.index("def system_conn(")]
    assert "with request_connection() as conn:" in body


def test_the_live_listener_and_every_side_connection_are_unpooled():
    """The LISTEN connection lives for the process and holds a session's LISTEN; the websocket's
    helpers, the RLS_REFUSED row and an approval's refusal are opened beside a request that
    already holds its own (docs/00 decision 233)."""
    expected = {
        "http/routers/live.py": "asyncio.to_thread(connect_request)",
        "http/errors.py": "with connect_request() as side",
        "approvals.py": "with connect_like(conn) as side",
    }
    for rel, opener in expected.items():
        text = (SRC / rel).read_text(encoding="utf-8")
        assert opener in text, rel
        names = _code_names(text)
        assert not names & {"request_connection", "db_pool", "get_conn"}, rel
    db_text = Path(db.__file__).read_text(encoding="utf-8")
    assert "return connect_request()" in db_text, "connect_like's request side is unpooled"


def test_ci_runs_the_security_suites_again_on_the_pool():
    """The pool is off outside production, so the suite alone never runs a request on a pooled
    connection: CI's first leg runs the security suites again with it on."""
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    step = ci[ci.index("- name: Security suites on the request pool"):]
    step = step[:step.index("\n      - name:")]
    assert "if: ${{ matrix.full }}" in step
    assert 'NOCTORNAL_DB_POOL: "on"' in step
    selection = re.search(r'-k "([^"]+)"', step).group(1)
    for word in ("rls", "session_binding", "hidden", "authz", "sample_origin", "download_ticket",
                 "break_glass", "db_pool"):
        assert re.search(rf"\b{word}\b", selection), word
    assert "and not downgrade" in selection, "the round trips cannot run on a used database"
    assert "skipped" in step, "a skip on the pooled run must fail it as on the first"


def _takes_get_conn(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    args = fn.args.args + fn.args.kwonlyargs
    defaults = [None] * (len(fn.args.args) - len(fn.args.defaults)) + list(fn.args.defaults) \
        + list(fn.args.kw_defaults)
    names = set()
    for arg, default in zip(args, defaults, strict=True):
        if (isinstance(default, ast.Call) and isinstance(default.func, ast.Name)
                and default.func.id == "Depends" and default.args
                and isinstance(default.args[0], ast.Name) and default.args[0].id == "get_conn"):
            names.add(arg.arg)
    return names


def test_no_route_closes_the_connection_it_was_given():
    """A route that closed its connection would cost the pool a reconnect at best; one that
    entered it as a context manager (`with conn:`) closes it too. `get_conn` gives it back."""
    offenders, seen = [], 0
    for path in sorted((SRC / "http").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            names = _takes_get_conn(fn)
            if not names:
                continue
            seen += 1
            for node in ast.walk(fn):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "close" and isinstance(node.func.value, ast.Name)
                        and node.func.value.id in names):
                    offenders.append(f"{path.name}:{node.lineno}")
                if isinstance(node, ast.With | ast.AsyncWith):
                    for item in node.items:
                        if (isinstance(item.context_expr, ast.Name)
                                and item.context_expr.id in names):
                            offenders.append(f"{path.name}:{node.lineno}")
    assert seen > 300, f"only {seen} routes found taking get_conn: the scan is broken"
    assert not offenders, offenders
