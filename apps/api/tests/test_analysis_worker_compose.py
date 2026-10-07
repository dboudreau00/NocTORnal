"""The production compose file runs the analysis worker isolated, and
wires every user of it (docs/17 F42, 2026-10-02).

The worker parses bytes written by the people under investigation, so its
service is held here to what makes it a sandbox rather than another
application container: no env_file and no setting but its own, no
network, a read-only root, no-new-privileges, pids and memory limits, and
(since the F42 review of 2026-10-02) root holding only kill, setgid and
setuid, with an init, so each child runs as a user of its own. Its
socket's volume is a tmpfs only it writes; api, collector and lab-triage
mount it read-only and name the same socket; nothing else mounts it (the
cron loop did until the collection poll moved to the collector, A collector
process, 2026-10-02).

Pure: the compose file is read with test_egress_topology's reader, which
fails closed on any construct it does not understand. That the container
really behaves so (cannot connect out, cannot see another container's
environment) was shown with docker on 2026-10-02, and
infra/production/README.md, Analysis worker, has the commands for a
human to repeat it.
"""
from __future__ import annotations

import pytest

from test_egress_topology import COMPOSE, Reader, _env_files, _nets

from noctornal_api import analysis_runner as ar
from noctornal_api import analysis_worker as aw

WORKER = "analysis-worker"
USERS = ("api", "collector", "lab-triage")
MOUNT = "/run/noctornal-analysis"


@pytest.fixture(scope="module")
def doc():
    return Reader(COMPOSE.read_text(encoding="utf-8")).document()


@pytest.fixture(scope="module")
def worker(doc):
    return doc["services"][WORKER]


#: process_facts() of the worker this file starts (F42 review, 2026-10-02).
COMPOSE_FACTS = {"euid": 0, "pid": 7, "capabilities": ["kill", "setgid", "setuid"],
                 "no_new_privileges": True, "read_only_root": True,
                 "state_left_open": []}


def test_the_worker_holds_no_secret_and_no_setting_but_its_own(worker, monkeypatch):
    assert _env_files(worker) == []
    env = worker["environment"]
    assert ar.foreign_environment(env) == []
    assert set(env) <= ar.WORKER_OWN_ENV
    # The service's environment and settings are ones the worker starts
    # with (on Linux, where it runs).
    monkeypatch.setattr(ar, "HAS_UNIX", True)
    assert aw.start_problems({**env, "PATH": "/usr/bin"},
                             facts={**COMPOSE_FACTS,
                                    "pids_max": int(worker["pids_limit"])}) == []


def test_the_worker_has_no_network(worker):
    assert worker["network_mode"] == "none"
    assert not _nets(worker)
    assert "ports" not in worker and "expose" not in worker
    assert "extra_hosts" not in worker and "dns" not in worker


def test_the_worker_is_confined(worker):
    assert worker["read_only"] is True
    assert worker["cap_drop"] == ["ALL"]
    assert "privileged" not in worker
    assert worker["security_opt"] == ["no-new-privileges:true"]
    assert int(worker["pids_limit"]) >= aw.pids_needed(
        int(worker["environment"][aw.CONCURRENCY_ENV]))
    assert worker["mem_limit"] and worker["memswap_limit"] == worker["mem_limit"]
    tmp = [t for t in worker["tmpfs"] if t.startswith("/tmp:")]
    assert len(tmp) == 1 and "noexec" in tmp[0] and "nosuid" in tmp[0]
    for shared in ("pid", "userns_mode", "cgroup"):
        assert shared not in worker, shared


def test_nothing_a_child_makes_outlives_its_request(worker):
    """F42 verify 2 (2026-10-03): the container's own IPC namespace with no
    /dev/shm, the sysctls that leave a child unable to create SysV or POSIX
    objects, and a /tmp no child's uid can write. The same values the
    worker reads from its own process (`state_left_open`) are the ones
    compose.yml sets, so the file and the check cannot drift apart."""
    # `ipc: none`, never `host` or a shared service: the reader keeps
    # scalars as text.
    assert worker["ipc"] == "none"
    sysctls = worker["sysctls"]
    assert set(sysctls) == set(aw.IPC_SYSCTLS) | {"kernel.sem"}
    for name in aw.IPC_SYSCTLS:
        assert sysctls[name] == "0", name
    assert sysctls["kernel.sem"].split() == ["0", "0", "0", "0"]
    tmp = [t for t in worker["tmpfs"] if t.startswith("/tmp:")][0]
    options = dict(part.partition("=")[::2] for part in tmp.split(":", 1)[1].split(","))
    mode = int(options["mode"], 8)
    assert aw._writable_by_others(0o040000 | mode, False) is False
    assert options["size"] in ("1m", "1M")


def test_the_worker_starts_under_the_compose_files_own_settings(worker, monkeypatch):
    """The facts compose.yml produces, as the worker would read them, leave
    nothing open and a pids limit inside its bounds."""
    monkeypatch.setattr(ar, "HAS_UNIX", True)
    env = {**worker["environment"], "PATH": "/usr/bin"}
    slots = int(worker["environment"][aw.CONCURRENCY_ENV])
    limit = int(worker["pids_limit"])
    assert aw.pids_needed(slots) <= limit <= aw.pids_ceiling(slots)
    facts = {**COMPOSE_FACTS, "pids_max": limit}
    assert aw.start_problems(env, facts=facts) == []
    # And each setting, taken out, is a refusal that names it.
    for opened in (["kernel.shmmax"], ["kernel.sem"], ["fs.mqueue.queues_max"],
                   ["/dev/shm"], ["/tmp"]):
        problems = aw.start_problems(env, facts={**facts, "state_left_open": opened})
        assert len(problems) == 1 and opened[0] in problems[0], opened


def test_the_worker_supervises_children_that_are_users_of_their_own(doc, worker):
    """F42 review (2026-10-02): root with kill, setgid and setuid only, so
    each child runs as a uid that is neither root, nor the application,
    nor shared with another slot; an init to reap what is killed."""
    uid, gid = worker["user"].split(":")
    assert (uid, gid) == ("0", "10001")
    assert sorted(worker["cap_add"]) == ["KILL", "SETGID", "SETUID"]
    assert {c.lower() for c in worker["cap_add"]} == aw.SUPERVISOR_CAPABILITIES
    assert worker["init"] is True
    assert "--shared-uid" not in worker["command"]
    children = [aw.CHILD_UID_BASE + n for n in range(16)]
    assert not {0, 10001, 10002} & set(children)
    app = doc["services"]["api"]["user"] if "user" in doc["services"]["api"] else None
    assert app is None or int(str(app).split(":")[0]) not in children


def test_the_worker_mounts_only_its_socket(worker):
    assert worker["volumes"] == [f"analysis-socket:{MOUNT}"]
    assert worker["environment"][ar.SOCKET_ENV].startswith(MOUNT + "/")
    assert ar.setting_problem({ar.SOCKET_ENV: worker["environment"][ar.SOCKET_ENV]}) is None


def test_the_worker_is_the_application_image_running_the_worker(doc, worker):
    # The image migrate builds, never pulled (one builder: the note above
    # x-noctornal-app in compose.yml, and test_g48_image_context).
    assert worker["image"] == doc["services"]["migrate"]["image"]
    assert "build" in doc["services"]["migrate"] and "build" not in worker
    assert worker["pull_policy"] == "never"
    assert worker["command"] == ["python", "-m", "noctornal_api.analysis_worker"]
    assert worker["healthcheck"]["test"] == [
        "CMD", "python", "-m", "noctornal_api.analysis_worker", "--check"]


def test_the_socket_volume_is_a_tmpfs_the_worker_alone_writes(doc, worker):
    from types import SimpleNamespace
    volume = doc["volumes"]["analysis-socket"]
    assert volume["driver"] == "local"
    opts = volume["driver_opts"]
    assert opts["type"] == "tmpfs" and opts["device"] == "tmpfs"
    o = dict(part.split("=", 1) for part in opts["o"].split(","))
    uid, gid = worker["user"].split(":")
    assert (o["uid"], o["gid"]) == (uid, gid)
    # Owner writes; the group (the application) may only pass through, and
    # a child's uid, in neither, may not even enter.
    assert o["mode"] == "0750"
    seen = SimpleNamespace(st_uid=int(o["uid"]), st_mode=0o040000 | int(o["mode"], 8))
    assert aw.socket_directory_problem(seen, euid=int(uid)) is None


def test_each_user_mounts_the_socket_read_only_and_names_the_same_one(doc, worker):
    path = worker["environment"][ar.SOCKET_ENV]
    for name in USERS:
        svc = doc["services"][name]
        assert f"analysis-socket:{MOUNT}:ro" in svc["volumes"], name
        assert "./tls:/certs:ro" in svc["volumes"], name
        assert svc["environment"][ar.SOCKET_ENV] == path, name
        assert ar.LOCAL_ENV not in svc["environment"], name
        assert WORKER in svc["depends_on"], name
    assert doc["services"]["lab-triage"]["depends_on"][WORKER]["condition"] == \
        "service_healthy"
    for name in ("api", "collector"):
        assert doc["services"][name]["depends_on"][WORKER]["condition"] == \
            "service_started"


def test_nothing_else_mounts_the_socket(doc):
    for name, svc in doc["services"].items():
        if name in USERS or name == WORKER:
            continue
        mounts = [v for v in svc.get("volumes") or [] if isinstance(v, str)]
        assert not any(v.startswith("analysis-socket:") for v in mounts), name
        assert ar.SOCKET_ENV not in (svc.get("environment") or {}), name


def test_the_image_the_worker_runs_carries_none_of_the_operators_secret_files():
    """F42 verify 5 (2026-10-03): the worker is the application image
    (`COPY . /app`), so a secret file the operator keeps beside compose.yml
    is baked into it unless .dockerignore excludes it, and the worker holds
    no secret only while that file's mode keeps a child out. Every secret
    path .gitignore names under infra/production is excluded from the
    build context, and the tracked templates are not."""
    import fnmatch

    from test_egress_topology import ROOT

    def lines(name):
        text = (ROOT / name).read_text(encoding="utf-8")
        return [ln.strip() for ln in text.splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")]

    secret_paths = [ln for ln in lines(".gitignore")
                    if ln.startswith("infra/production/")]
    assert {"infra/production/secrets.env", "infra/production/egress-proxy.env",
            "infra/production/egress-client.env",
            "infra/production/postgres-init.env",
            "infra/production/tls/"} <= set(secret_paths), "the scan found nothing"
    rules = lines(".dockerignore")

    def excluded(path: str) -> bool:
        """Docker's reading: the last rule that matches decides, and a `!`
        rule puts a path back (the tracked `.example` templates)."""
        verdict = False
        for rule in rules:
            negate = rule.startswith("!")
            pattern = rule[1:] if negate else rule
            if pattern.endswith("/"):
                hit = path.startswith(pattern)
            else:
                hit = fnmatch.fnmatchcase(path, pattern)
            if hit:
                verdict = not negate
        return verdict

    for path in secret_paths:
        assert excluded(path if not path.endswith("/") else path + "private.key"), path
    for template in ("infra/production/secrets.env.example",
                     "infra/production/egress-proxy.env.example",
                     "infra/production/egress-client.env.example",
                     "infra/production/postgres-init.env.example"):
        assert not excluded(template), template
