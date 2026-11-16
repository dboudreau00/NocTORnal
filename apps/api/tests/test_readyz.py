"""`GET /readyz`: whether this process can serve, the question a cluster's readiness probe asks.

Ready is the database answering and the schema being at the head of db/migrations, and nothing else:
not Redis, not the store, not the egress proxy, not the worker (readyz.py says why). The body is
`{"status": "ok"}` or `{"status": "unavailable"}`, never a version, a revision or a reason, and the
verdict is held and asked by one caller at a time, so an unauthenticated flood costs the database one
connection a window, and the callers that find it being asked are answered at once, so a database that
never answers cannot hold the server's threads that /healthz needs.

Env-gated on DATABASE_URL: the ready path reads `public.alembic_version` of the suite's own database.
"""
from __future__ import annotations

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set; /readyz is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

APP = "https://app.example"
SAMPLES = "https://samples.example"
DOWN_URL = "postgresql://nobody:hunter2-never-logged@127.0.0.1:1/nowhere"


@pytest.fixture(autouse=True)
def fresh_verdict():
    from noctornal_api import readyz
    readyz.forget()
    yield
    readyz.forget()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def test_readyz_is_unauthenticated_and_names_no_version_and_no_reason(client):
    """A stranger is told ready or not. The build, the revision and the reason are not for them."""
    from noctornal_api import readyz
    heads = readyz.migration_heads()
    r = client.get("/readyz")
    assert r.status_code == 200, r.text
    assert r.json() == {"status": "ok"}
    assert r.headers["cache-control"] == "no-store"
    assert not any(head in r.text for head in heads)
    assert "version" not in r.text.lower()


def test_readyz_is_503_until_the_schema_is_at_head_pg(client, monkeypatch, caplog):
    """Compose gets this from depends_on the migrate service completing; a pod has no such thing, so
    the probe has to say so: a database stamped at something other than the scripts' head is not ready."""
    from noctornal_api import readyz
    monkeypatch.setattr(readyz, "migration_heads", lambda directory=None: ["9999"])
    with caplog.at_level(logging.WARNING, logger="noctornal.readyz"):
        r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json() == {"status": "unavailable"}
    assert "9999" not in r.text and "head" not in r.text
    assert "schema_not_at_head" in caplog.text
    monkeypatch.undo()
    readyz.forget()
    assert client.get("/readyz").status_code == 200


def test_readyz_is_503_when_the_database_is_down(client, monkeypatch, caplog):
    """An unreachable database is not ready, and the log names the class and never the DSN."""
    monkeypatch.setenv("DATABASE_URL", DOWN_URL)
    with caplog.at_level(logging.INFO, logger="noctornal.readyz"):
        r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json() == {"status": "unavailable"}
    assert "database_unreachable" in caplog.text
    assert "hunter2" not in caplog.text and "hunter2" not in r.text


def test_readyz_is_503_when_there_is_no_database_url(client, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json() == {"status": "unavailable"}


def test_readyz_costs_at_most_one_database_connection_per_window_whatever_the_traffic(
        client, monkeypatch):
    """The endpoint is open and opens a connection, against a max_connections of 200: forty callers at
    once, and a hundred more, cost one connection, and the next window costs one."""
    import psycopg

    from noctornal_api import readyz
    opened: list[int] = []
    real = psycopg.connect

    def counting(*args, **kwargs):
        if kwargs.get("connect_timeout") == readyz.CONNECT_TIMEOUT_S:
            opened.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(psycopg, "connect", counting)
    barrier = threading.Barrier(40)

    def ask() -> bool:
        barrier.wait(10)
        return readyz.verdict()

    with ThreadPoolExecutor(40) as pool:
        answers = list(pool.map(lambda _i: ask(), range(40)))
    # The one that asked the database says ready. A caller that finds the question in flight is not
    # made to wait for it and, with no earlier verdict to repeat, is told not ready.
    assert True in answers
    assert len(opened) == 1
    readyz.forget()
    opened.clear()
    assert readyz.verdict() is True
    with ThreadPoolExecutor(40) as pool:
        answers = list(pool.map(lambda _i: ask(), range(40)))
    assert answers == [True] * 40
    for _ in range(100):
        assert client.get("/readyz").status_code == 200
    assert len(opened) == 1, "one connection for the whole window, not one per caller"
    readyz._known = (0.0, None)
    assert client.get("/readyz").status_code == 200
    assert len(opened) == 2, "the next window asks again"


def test_callers_that_find_the_question_in_flight_are_answered_at_once_and_healthz_is_not_delayed(
        monkeypatch):
    """The endpoint is open and /readyz is exempt from the limiter, so sixty probes at a database that
    accepts and never answers must not park the server's threads on a lock: the one that asks waits, the
    others are told the last verdict (or not ready) and /healthz, the liveness probe, is answered while
    it waits. One shared event loop, as a real server has, since the limit is per loop."""
    import time

    from fastapi.testclient import TestClient

    from noctornal_api import readyz
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter

    entered = threading.Event()
    release = threading.Event()
    asked: list[int] = []

    def hung(*_a, **_k):
        asked.append(1)
        entered.set()
        release.wait(20)
        return None

    monkeypatch.setattr(readyz, "schema_problem", hung)
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    answers: list[int] = []
    with TestClient(app) as shared:
        with ThreadPoolExecutor(61) as pool:
            first = pool.submit(lambda: shared.get("/readyz").status_code)
            assert entered.wait(10)
            others = [pool.submit(lambda: shared.get("/readyz").status_code) for _ in range(60)]
            started = time.monotonic()
            for other in others:
                answers.append(other.result(timeout=10))
            waited = time.monotonic() - started
            started = time.monotonic()
            assert shared.get("/healthz").status_code == 200
            healthz_s = time.monotonic() - started
            release.set()
            assert first.result(timeout=10) == 200
    assert answers == [503] * 60, "no verdict yet, so not ready, and nobody waited for the database"
    assert waited < 5 and healthz_s < 1.0, (waited, healthz_s)
    assert len(asked) == 1, "one question to the database for the whole flood"


def test_a_caller_in_flight_is_told_the_last_verdict_not_a_guess(monkeypatch):
    """With an earlier answer to repeat, a caller that finds the question in flight gets it, in either
    direction, and a computation that fails leaves the next caller free to ask."""
    import time

    from noctornal_api import readyz
    gate = threading.Event()
    entered = threading.Event()

    def slow(*_a, **_k):
        entered.set()
        gate.wait(10)
        return None

    for last, expected in ((None, True), ("schema_not_at_head", False)):
        gate.clear()
        entered.clear()
        readyz.forget()
        readyz._known = (time.monotonic() - 1.0, last)
        monkeypatch.setattr(readyz, "schema_problem", slow)
        with ThreadPoolExecutor(2) as pool:
            asking = pool.submit(readyz.verdict)
            assert entered.wait(10)
            assert readyz.verdict() is expected
            gate.set()
            assert asking.result(timeout=10) is True

    def broken(*_a, **_k):
        raise RuntimeError("never a verdict")

    readyz.forget()
    monkeypatch.setattr(readyz, "schema_problem", broken)
    with pytest.raises(RuntimeError):
        readyz.verdict()
    assert readyz._computing is False, "a failed question must not leave the next caller waiting"


def test_a_failed_verdict_is_held_too(client, monkeypatch):
    """A database that is down is asked once a window, not once a probe."""
    import psycopg

    from noctornal_api import readyz
    monkeypatch.setenv("DATABASE_URL", DOWN_URL)
    opened: list[int] = []
    real = psycopg.connect

    def counting(*args, **kwargs):
        opened.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(psycopg, "connect", counting)
    for _ in range(5):
        assert client.get("/readyz").status_code == 503
    assert len(opened) == 1
    assert readyz._known is not None


def test_the_sample_origin_serves_readyz_and_still_404s_everything_else(client, monkeypatch):
    """The sample origin is the same codebase as the application and serves only what it is allowed
    to; a probe of its pod needs /readyz, and that must not widen what else it answers."""
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)
    assert client.get("/readyz").status_code == 200
    assert client.get("/healthz").status_code == 200
    for path in ("/ui/", "/", "/api/v1/cases", "/api/v1/samples", "/readyz/", "/readyz.json",
                 "/api/v1/readyz"):
        assert client.get(path).status_code == 404, path
    assert client.post("/readyz").status_code in (404, 405)


# ---------------------------------------------------------------------------
# scripts/wait_for_schema.py: the same question for a pod that serves no HTTP
# ---------------------------------------------------------------------------

def _wait_script():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[3] / "scripts" / "wait_for_schema.py"
    spec = importlib.util.spec_from_file_location("wait_for_schema_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_wait_for_schema_exits_0_at_head_and_1_on_timeout_pg(monkeypatch, capsys):
    """An init container holds a pod back until the migration Job is done: 0 once the schema is at
    head, 1 when the wait ran out, and what it prints names a class and never a revision."""
    import time

    from noctornal_api import readyz
    script = _wait_script()
    assert script.main([]) == 0
    assert "at head" in capsys.readouterr().out
    monkeypatch.setattr(readyz, "migration_heads", lambda directory=None: ["9999"])
    monkeypatch.setattr(script, "INTERVAL_S", 0.05)
    started = time.monotonic()
    assert script.main(["--wait", "0.3"]) == 1
    assert 0.25 <= time.monotonic() - started < 5
    err = capsys.readouterr().err
    assert "schema_not_at_head" in err and "9999" not in err
    assert script.main([]) == 1, "asked once, it does not wait"


def test_wait_for_schema_waits_for_a_schema_that_arrives(monkeypatch):
    """The Job finishes while the init container waits: the next question is answered ready."""
    from noctornal_api import readyz
    script = _wait_script()
    real = readyz.schema_problem
    asked = []

    def late(*args, **kwargs):
        asked.append(1)
        return "schema_not_at_head" if len(asked) < 3 else real(*args, **kwargs)

    monkeypatch.setattr(readyz, "schema_problem", late)
    monkeypatch.setattr(script, "INTERVAL_S", 0.01)
    assert script.main(["--wait", "30"]) == 0
    assert len(asked) == 3


def test_wait_for_schema_refuses_a_wait_it_will_not_make(capsys):
    script = _wait_script()
    for value in ("-1", "3601", "nan"):
        with pytest.raises(SystemExit) as done:
            script.main(["--wait", value])
        assert done.value.code == 2, value


def test_wait_for_schema_refuses_the_owner_credential(monkeypatch, capsys):
    """Like every job: the schema owner's password or DSN on a runtime process is refused by name, before
    anything is connected to, with the code a refusal has."""
    import psycopg

    from noctornal_api import config
    from test_config_boot import _production
    script = _wait_script()
    for name, value in _production().items():
        monkeypatch.setenv(name, value)
    for found in config.published_credentials():
        monkeypatch.delenv(found.variable, raising=False)
    monkeypatch.setenv(config.OWNER_PASSWORD_ENV, "Hq7vX2-owner")

    def connected(*_a, **_k):
        raise AssertionError("connected before the environment check")

    monkeypatch.setattr(psycopg, "connect", connected)
    assert script.main([]) == config.JOB_REFUSAL_EXIT
    err = capsys.readouterr().err
    assert err.startswith("wait_for_schema: refusing to run: POSTGRES_PASSWORD is set on a runtime process")
    assert "Hq7vX2-owner" not in err
