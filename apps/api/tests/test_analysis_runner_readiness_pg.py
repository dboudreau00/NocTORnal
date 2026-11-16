"""The readiness row `sample_static_analysis` tells the truth about where analysis runs (docs/17 F42).

Development's local child passes and says it is local; a production that chose the local child out
loud fails and says so; the isolated worker passes only on its own account (a clean environment,
children that are users of their own, three capabilities, no-new-privileges, a read-only root,
loopback only, a child that cannot reach the database host) and says where it is. The paths that fail
before the queue is read, and the pass and fail with the queue fixed, are test_analysis_runner.py's;
these read this database's real triage queue.

No hedge: an assertion of "passes, or fails for the queue" cannot fail. The queue's state is read here
by the row's own rule, and the row must agree with it exactly.

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
                  max(finished_at)
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
    """A worker with a network interface besides loopback, or none reported, fails the row rather than
    passing with a caveat or nothing at all."""
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


# ---------------------------------------------------------------------------
# A worker reached over mutual TLS is a pod: judged by the self-test, not the interface list
# ---------------------------------------------------------------------------

@pytest.fixture
def pod(conn, monkeypatch, tmp_path):
    """The TLS worker, as the register reads a pod's: one interface besides loopback, and a self-test the
    test decides. Returns a function that runs the row and the probe the self-test was given."""
    from test_analysis_worker_tcp_tls import make_pki, tls_worker

    pki = make_pki(tmp_path / "pki")
    real = aw.Worker.status
    probes: list[dict] = []

    def run(*, exposure, interfaces=("lo", "eth0"), canary=None, **account_over):
        def account(self):
            out = real(self)
            out.update(CLEAN_ACCOUNT)
            out.update({"network_interfaces": list(interfaces), "transport": "tcp_tls",
                        **account_over})
            return out

        real_selftest = lab_triage.selftest

        def selftest(settings, **kw):
            probes.append(kw.get("probe") or {})
            out = real_selftest(settings, **kw)
            out["exposure"] = {"proc_environ_readable": True, **exposure}
            return out

        monkeypatch.setattr(aw.Worker, "status", account)
        monkeypatch.setattr(lab_triage, "selftest", selftest)
        with tls_worker(pki) as (_w, port):
            monkeypatch.setenv(ar.ADDR_ENV, f"127.0.0.1:{port}")
            monkeypatch.setenv(ar.TLS_CERT_ENV, str(pki.client_cert))
            monkeypatch.setenv(ar.TLS_KEY_ENV, str(pki.client_key))
            monkeypatch.setenv(ar.TLS_CA_ENV, str(pki.ca))
            monkeypatch.delenv(ar.SOCKET_ENV, raising=False)
            monkeypatch.delenv(ar.LOCAL_ENV, raising=False)
            if canary:
                monkeypatch.setenv("NOCTORNAL_EGRESS_CANARY", canary)
            else:
                monkeypatch.delenv("NOCTORNAL_EGRESS_CANARY", raising=False)
            return readiness._sample_static_analysis(conn), probes

    return run


def test_a_pod_worker_passes_on_one_interface_and_a_self_test_that_reaches_nothing(pod):
    check, probes = pod(exposure={"database_reachable": False, "canary_reachable": False},
                        canary="10.99.0.9:9")
    assert check.evidence.startswith("Analysis runs in the isolated worker at 127.0.0.1:")
    assert ("1 network interface besides loopback (eth0), whose isolation the self-test proves "
            "and the interface list does not") in check.evidence
    assert "no network interface but loopback" not in check.evidence
    assert "cannot reach the database host or the canary." in check.evidence
    assert check.ok is (not _stale_now(check)), check
    assert probes[0]["canary"] == {"host": "10.99.0.9", "port": 9}


def _stale_now(check) -> bool:
    return SCHEDULE in (check.action or "")


def test_a_pod_worker_with_no_canary_says_only_the_database_host(pod):
    check, probes = pod(exposure={"database_reachable": False, "canary_reachable": None})
    assert "Its analysis child cannot reach the database host." in check.evidence
    assert "canary" not in check.evidence
    assert "canary" not in probes[0]


def test_a_pod_worker_with_two_interfaces_fails(pod):
    check, _ = pod(exposure={"database_reachable": False, "canary_reachable": False},
                   interfaces=("lo", "eth0", "net1"))
    assert check.ok is False
    assert "2 network interfaces besides loopback (eth0, net1)" in check.evidence
    assert "single network interface" in check.action


def test_a_pod_worker_whose_child_reaches_the_canary_is_not_isolated(pod):
    check, _ = pod(exposure={"database_reachable": False, "canary_reachable": True},
                   canary="10.99.0.9:9")
    assert check.ok is False
    assert "egress canary (NOCTORNAL_EGRESS_CANARY)" in check.evidence
    assert "the worker is not isolated" in check.evidence
    assert "NetworkPolicy" in check.action and "network_mode" not in check.action


def test_a_pod_worker_whose_child_reaches_the_database_is_not_isolated_and_is_told_the_policy(pod):
    check, _ = pod(exposure={"database_reachable": True, "canary_reachable": False})
    assert check.ok is False
    assert "database host, so the worker is not isolated" in check.evidence
    assert "NetworkPolicy" in check.action and "network_mode" not in check.action


def test_a_pod_worker_is_handed_the_addresses_its_names_resolve_to(pod, monkeypatch):
    """A pod's worker has no DNS, so a name given to its child could never resolve and "cannot reach"
    would be true whatever the policy did to the address. This process resolves; the child is handed
    literals (a literal passes as it is)."""
    import socket
    real = socket.getaddrinfo
    table = {"postgres.noctornal.svc": "10.96.0.12", "egress-canary.noctornal.svc": "10.96.0.99"}

    def fake(host, port, *args, **kwargs):
        if host in table:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (table[host], port or 0))]
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@postgres.noctornal.svc:5432/n")
    check, probes = pod(exposure={"database_reachable": False, "canary_reachable": False},
                        canary="egress-canary.noctornal.svc:9")
    assert probes[0]["host"] == "10.96.0.12" and probes[0]["port"] == 5432
    assert probes[0]["canary"] == {"host": "10.96.0.99", "port": 9}
    assert "postgres.noctornal.svc" not in check.evidence
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@10.0.0.5:5432/n")
    _, probes = pod(exposure={"database_reachable": False, "canary_reachable": False},
                    canary="10.99.0.9:9")
    assert probes[1]["host"] == "10.0.0.5" and probes[1]["canary"]["host"] == "10.99.0.9"


def test_a_name_that_does_not_resolve_here_is_not_handed_to_the_child_and_is_not_tried(
        pod, monkeypatch):
    """The child of a pod's worker has no DNS: a lookup it cannot make would only run out its time
    limit. This process drops what it cannot resolve and the row fails naming what was not tried."""
    import socket
    real = socket.getaddrinfo
    gone = {"postgres.noctornal.svc", "egress-canary.noctornal.svc"}

    def fake(host, port, *args, **kwargs):
        if host in gone:
            raise socket.gaierror(socket.EAI_NONAME, "no such name")
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@postgres.noctornal.svc:5432/n")
    check, probes = pod(exposure={"database_reachable": None, "canary_reachable": None},
                        canary="egress-canary.noctornal.svc:9")
    assert "host" not in probes[0] and "canary" not in probes[0]
    assert check.ok is False
    assert "the database host and the canary were not tried" in check.evidence


@pytest.mark.parametrize("exposure, canary, names", [
    # The child reports names it could not resolve: nothing was tried.
    ({"database_reachable": False, "canary_reachable": False, "unresolved": ["database"]},
     "10.99.0.9:9", "the database host was not tried"),
    ({"database_reachable": False, "canary_reachable": False, "unresolved": ["canary"]},
     "10.99.0.9:9", "the canary was not tried"),
    ({"database_reachable": False, "canary_reachable": False,
      "unresolved": ["database", "canary"]},
     "10.99.0.9:9", "the database host and the canary were not tried"),
    # No usable target at all.
    ({"database_reachable": None, "canary_reachable": None}, None,
     "the database host was not tried"),
    # A canary was declared and the child was not given it.
    ({"database_reachable": False, "canary_reachable": None}, "10.99.0.9:9",
     "the canary was not tried"),
])
def test_a_pod_worker_whose_self_test_tried_nothing_is_not_proved_isolated(
        pod, exposure, canary, names):
    """An answer of "no" to a name the worker cannot look up, or to nothing at all, is not isolation: the
    row fails and says what was not tried, and does not claim the child cannot reach the host."""
    check, _ = pod(exposure=exposure, canary=canary)
    assert check.ok is False
    assert names in check.evidence and "so it is not proved" in check.evidence
    assert "cannot reach the database host" not in check.evidence
    assert "NetworkPolicy" in check.action and "network_mode" not in check.action


def test_a_compose_worker_still_says_network_mode_and_loopback_only(
        conn, monkeypatch, clean_worker):
    """The Unix transport's rule and its action are what they were: a worker with a second interface
    fails, and is told to run with network_mode none."""
    monkeypatch.setattr(aw.Worker, "status",
                        lambda self: clean_worker(self, network_interfaces=["lo", "eth0"]))
    with tcp_worker() as (_w, connect):
        _isolated(monkeypatch, connect)
        check = readiness._sample_static_analysis(conn)
    assert check.ok is False and "network_mode none" in check.action


def test_a_declared_pids_limit_passes_and_says_it_was_told_and_not_read(pod):
    check, _ = pod(exposure={"database_reachable": False, "canary_reachable": False},
                   pids_max=128, pids_max_source="declared")
    assert "a pids limit of 128 for 2 slots, declared and not read;" in check.evidence
    assert "NOCTORNAL_ANALYSIS_PIDS_LIMIT, not read" in (check.caveat or "")
    assert "podPidsLimit" in check.caveat


def test_a_pids_limit_read_from_the_cgroup_carries_no_such_caveat(pod):
    check, _ = pod(exposure={"database_reachable": False, "canary_reachable": False},
                   pids_max=128, pids_max_source="cgroup")
    assert "declared" not in check.evidence
    assert "podPidsLimit" not in (check.caveat or "")


def test_a_declared_pids_limit_outside_the_window_fails_and_names_the_variable_and_the_nodes(pod):
    check, _ = pod(exposure={"database_reachable": False, "canary_reachable": False},
                   pids_max=8, pids_max_source="declared")
    assert check.ok is False
    assert "The pids limit declared in NOCTORNAL_ANALYSIS_PIDS_LIMIT is 8" in check.evidence
    assert "podPidsLimit" in check.action and "NOCTORNAL_ANALYSIS_PIDS_LIMIT" in check.action
    assert "compose.yml" not in check.action
