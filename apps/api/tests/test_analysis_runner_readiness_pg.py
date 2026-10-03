"""The readiness row `sample_static_analysis` tells the truth about where
analysis runs (docs/17 F42, 2026-10-02).

Development's local child passes and says it is local; a production that
chose the local child out loud fails and says so; the isolated worker
passes only on its own account (a clean environment, children that are
users of their own, three capabilities, no-new-privileges, a read-only
root, loopback only, a child that cannot reach the database host) and
says where it is. The paths that fail before the queue is read, and the
pass and fail with the queue fixed, are test_analysis_runner.py's; these
read this database's real triage queue.

No hedge (F42 review, 2026-10-02): the assertions used to read "passes,
or fails for the queue", which cannot fail. The queue's state is read
here by the row's own rule, and the row must agree with it exactly.

Env-gated on DATABASE_URL. Writes nothing.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from test_analysis_runner import CLEAN_ACCOUNT, SOCK, tcp_worker

from noctornal_api import analysis_runner as ar
from noctornal_api import analysis_worker as aw
from noctornal_api import lab_triage, readiness

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

SCHEDULE = "schedule scripts/lab_triage.py"


@pytest.fixture(autouse=True)
def fresh_verdicts():
    ar.forget_verdicts()
    yield
    ar.forget_verdicts()


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    c.close()


def _stale(conn) -> bool:
    """The row's own rule for "nothing is running static triage", read
    from the same table."""
    depth, oldest, last_done = conn.execute(
        """SELECT count(*) FILTER (WHERE status = 'QUEUED'),
                  min(queued_at) FILTER (WHERE status = 'QUEUED'),
                  max(finished_at) FILTER (WHERE status = 'DONE')
             FROM lab.static_run""").fetchone()
    now = datetime.now(timezone.utc)
    stale = timedelta(minutes=readiness._TRIAGE_STALE_MINUTES)
    return bool(depth and oldest and now - oldest > stale
                and (last_done is None or now - last_done > stale))


@pytest.fixture
def clean_worker(monkeypatch):
    """The in-process worker's account as the container's would read: its
    own settings only, children that are users of their own, loopback only
    (the test process itself is none of those, which the worker in
    compose.yml is)."""
    real = aw.Worker.status

    def account(self, **over):
        out = real(self)
        out.update(CLEAN_ACCOUNT)
        out.update(over)
        return out

    monkeypatch.setattr(aw.Worker, "status", account)
    real_selftest = lab_triage.selftest

    def unreachable(settings, **kw):
        out = real_selftest(settings, **kw)
        out["exposure"] = {"proc_environ_readable": True,
                           "database_reachable": False}
        return out

    monkeypatch.setattr(lab_triage, "selftest", unreachable)
    return account


def _isolated(monkeypatch, connect):
    monkeypatch.setattr(ar, "HAS_UNIX", True)
    monkeypatch.setattr(ar, "_connect_unix", connect)
    monkeypatch.setenv(ar.SOCKET_ENV, SOCK)
    monkeypatch.delenv(ar.LOCAL_ENV, raising=False)


def test_the_local_child_in_development_passes_and_says_it_is_local(conn, monkeypatch):
    monkeypatch.delenv(ar.SOCKET_ENV, raising=False)
    monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
    check = readiness._sample_static_analysis(conn)
    assert check.evidence.startswith("Analysis runs in local child processes on this host.")
    stale = _stale(conn)
    assert check.ok is (not stale)
    assert (SCHEDULE in (check.action or "")) is stale


def test_a_production_that_chose_the_local_child_fails_out_loud(conn, monkeypatch):
    monkeypatch.delenv(ar.SOCKET_ENV, raising=False)
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.setenv(ar.LOCAL_ENV, "1")
    check = readiness._sample_static_analysis(conn)
    assert not check.ok
    assert "by explicit choice (NOCTORNAL_ANALYSIS_LOCAL=1)" in check.evidence
    assert "unset NOCTORNAL_ANALYSIS_LOCAL" in check.action
    assert "analysis-worker" in check.action
    assert (SCHEDULE in check.action) is _stale(conn)


def test_the_isolated_worker_passes_on_its_own_account_and_says_where(
        conn, monkeypatch, clean_worker):
    with tcp_worker() as (_w, connect):
        _isolated(monkeypatch, connect)
        check = readiness._sample_static_analysis(conn)
    assert check.evidence.startswith(f"Analysis runs in the isolated worker at {SOCK}")
    assert "3 environment variables, none a secret and none a setting but its own" \
        in check.evidence
    assert "each child a user of its own" in check.evidence
    assert "no network interface but loopback" in check.evidence
    assert "cannot reach the database host" in check.evidence
    stale = _stale(conn)
    assert check.ok is (not stale)
    assert (SCHEDULE in (check.action or "")) is stale
    # The worker's own /proc/1/environ holds nothing: not an exposure.
    assert "secrets" not in (check.caveat or "")


@pytest.mark.parametrize("interfaces, says", [
    (["lo", "eth0"], "network interface besides loopback (eth0)"),
    (None, "did not report its network interfaces"),
])
def test_a_worker_with_a_network_interface_or_none_reported_fails(
        conn, monkeypatch, clean_worker, interfaces, says):
    """F42 review (2026-10-02): both passed, with a caveat or nothing at
    all; the review's probe_ready.py printed ok = True for each."""
    monkeypatch.setattr(aw.Worker, "status",
                        lambda self: clean_worker(self, network_interfaces=interfaces))
    with tcp_worker() as (_w, connect):
        _isolated(monkeypatch, connect)
        check = readiness._sample_static_analysis(conn)
    assert check.ok is False
    assert says in check.evidence
    assert "network_mode none" in check.action


def test_a_worker_whose_children_share_its_user_fails(conn, monkeypatch, clean_worker):
    monkeypatch.setattr(aw.Worker, "status", lambda self: clean_worker(
        self, children={"isolation": "shared_uid", "uids": None, "max_tasks": None}))
    with tcp_worker() as (_w, connect):
        _isolated(monkeypatch, connect)
        check = readiness._sample_static_analysis(conn)
    assert check.ok is False
    assert "outlive its request" in check.evidence
    assert "without --shared-uid" in check.action
