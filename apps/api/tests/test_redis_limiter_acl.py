"""Redis isolation, enforced: the limiter's own Redis user (ROADMAP-REMAINING
"Redis isolation, enforced"; 2026-10-02).

Until this date `redis_limiter_isolated` could only REPORT keys somebody
else had written to the limiter's Redis, and the production Redis had one
user, `default`, holding every command on every key behind one password.
Now infra/production/compose.yml starts Redis with an ACL file in which
`default` is off and `noctornal_limiter` may touch keys under `rl:` and run
the commands the limiter sends, and nothing else.

Held here:

* the compose file writes exactly `ratelimit_redis.limiter_acl_rules()`,
  disables `default`, uses no `requirepass`, refuses a REDIS_URL naming it
  that does not sign in as the limiter and starts idle for one naming
  another host (its start script RUN under sh since the review of
  2026-10-02), and health-checks as the limiter;
* the limiter sends no CLIENT SETINFO, so the ACL grants none, and CI
  starts the ACL Redis the real-Redis leg below needs, so it never skips;
* `LIMITER_ACL_COMMANDS` covers every command the limiter's code sends
  (the Lua script's calls included) and is what the readiness row allows;
* the readiness row parses ACL GETUSER in every shape Redis has used, and
  under NOCTORNAL_ENV=production fails closed on each way the isolation
  can be missing, while a development Redis still passes on its census;
* `maxmemory_policy` asks INFO first, so the production user needs no
  CONFIG.

The last section runs against a Redis started with the compose file's own
start script when NOCTORNAL_TEST_ACL_REDIS_URL is set (the limiter's URL on
it), and against a second user on that server when
NOCTORNAL_TEST_ACL_REDIS_TENANT_URL is set. Nothing else needs a server.
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import pytest

from acl_redis_support import TENANT_USER, posix_shell, run_start_script, start_script
from noctornal_api import readiness
from noctornal_api.ratelimit_redis import (
    _GCRA_LUA,
    LIMITER_ACL_COMMANDS,
    LIMITER_ACL_USER,
    RedisBackend,
    limiter_acl_rules,
    limiter_key_prefix,
)
from test_egress_topology import Reader

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "infra" / "production" / "compose.yml"
SECRETS_EXAMPLE = ROOT / "infra" / "production" / "secrets.env.example"
PASSWORD = "Zm4tR-acl"


@pytest.fixture(scope="module")
def redis_service():
    return Reader(COMPOSE.read_text(encoding="utf-8")).document()["services"]["redis"]


def _script(service) -> str:
    assert service["command"][:2] == ["/bin/sh", "-c"]
    return service["command"][2]


# ---------------------------------------------------------------------------
# The compose file's ACL
# ---------------------------------------------------------------------------

def test_the_compose_acl_is_the_rule_the_code_states(redis_service):
    script = _script(redis_service)
    lines = re.findall(r"printf '(user [^']*)\\n'", script)
    assert lines == [
        "user default off resetpass resetkeys resetchannels -@all",
        f"user {LIMITER_ACL_USER} on #%s {limiter_acl_rules()}",
    ], lines
    assert limiter_acl_rules().startswith("resetkeys ~rl:* resetchannels -@all +")


def test_the_server_runs_the_acl_file_and_no_requirepass(redis_service):
    script = _script(redis_service)
    assert "--aclfile /tmp/users.acl" in script
    assert "requirepass" not in script
    # The password reaches the file as its SHA-256 only, written private.
    assert "umask 077" in script
    assert "sha256sum" in script and '"$$hash"' in script
    assert "--maxmemory-policy noeviction" in script


# The start check, RUN (review of 2026-10-02): the compose file's own script
# under sh, with `echo` where redis-server is exec'd. Until then it was read
# as text, and a REDIS_URL naming the operator's own Redis was refused with
# a pointer to the installer step, which leaves such a URL alone.

needs_sh = pytest.mark.skipif(posix_shell() is None, reason="no POSIX sh on this machine")
_PW = "Sx4-acl-pass"


def _start(tmp_path, url, password=_PW):
    return run_start_script({"REDIS_PASSWORD": password, "REDIS_URL": url}, tmp_path)


@needs_sh
@pytest.mark.parametrize("url", [
    f"redis://{LIMITER_ACL_USER}:{_PW}@redis:6379/0",
    f"redis://{LIMITER_ACL_USER}:{_PW}@redis",
])
def test_the_limiters_url_on_this_redis_starts_it(tmp_path, url):
    code, out, err, acl = _start(tmp_path, url)
    assert code == 0 and err == "", err
    assert out.startswith("redis-server ") and "--aclfile" in out
    assert acl.splitlines()[0] == "user default off resetpass resetkeys resetchannels -@all"
    assert acl.splitlines()[1] == (f"user {LIMITER_ACL_USER} on "
                                   f"#{hashlib.sha256(_PW.encode()).hexdigest()} "
                                   f"{limiter_acl_rules()}")
    assert _PW not in acl, "the password itself reached the ACL file"


@needs_sh
@pytest.mark.parametrize("url", [
    f"redis://:{_PW}@redis:6379/0",                         # an older secrets.env: default
    "redis://redis:6379/0",                                 # no password at all
    f"redis://{LIMITER_ACL_USER}:stale@redis:6379/0",       # another password
    f"rediss://{LIMITER_ACL_USER}:{_PW}@redis:6379/0",      # TLS this Redis does not speak
    f"redis://other:{_PW}@redis:6379/0",
    f"redis://:{_PW}@REDIS:6379/0",                         # a host name has no case: the
    f"redis://:{_PW}@Redis",                                # installer reads these as `redis`
    "unix:///run/redis.sock",                               # no host
    "",
    "not a url",
])
def test_anything_else_naming_this_redis_refuses_the_start(tmp_path, url):
    code, out, err, acl = _start(tmp_path, url)
    assert code == 1 and out == "" and acl == "", (code, out, err)
    assert "refusing to start" in err
    assert "sudo ./release/install.sh" in err and "--production-secrets" in err
    assert "release/secrets-upgrade/README.md" in err
    assert _PW not in err and "stale" not in err, "the refusal printed a value"


@needs_sh
@pytest.mark.parametrize("url", [
    f"redis://cache-user:{_PW}@cache.corp.example:6380/0",
    "rediss://limiter:secret-9@redis.example.gov:6380/0",
    f"redis://{LIMITER_ACL_USER}:other-pass@10.20.30.40:6379/0",
])
def test_a_url_naming_another_host_starts_this_redis_idle_and_says_so(tmp_path, url):
    """The operator's own Redis is theirs to secure: this one starts with
    its ACL and no client, so the services waiting on it start."""
    code, out, err, acl = _start(tmp_path, url)
    assert code == 0, err
    assert out.startswith("redis-server ") and len(acl.splitlines()) == 2
    assert "names a Redis on another host" in err
    assert "infra/production/README.md" in err
    for secret in (_PW, "secret-9", "other-pass", "corp.example", "10.20.30.40"):
        assert secret not in err


@needs_sh
def test_an_empty_password_refuses_the_start(tmp_path):
    code, _out, err, acl = _start(tmp_path, f"redis://{LIMITER_ACL_USER}:@redis:6379/0",
                                  password="")
    assert code == 1 and acl == "" and "REDIS_PASSWORD is empty" in err


def test_the_healthcheck_signs_in_as_the_limiter(redis_service):
    test = redis_service["healthcheck"]["test"]
    assert test[0] == "CMD-SHELL"
    assert f"--user {LIMITER_ACL_USER}" in test[1] and "ping" in test[1]


def test_the_template_url_names_the_user():
    text = SECRETS_EXAMPLE.read_text(encoding="utf-8")
    url = re.search(r"^REDIS_URL=(.*)$", text, re.M).group(1)
    assert urlsplit(url).username == LIMITER_ACL_USER
    assert urlsplit(url).hostname == "redis"


def test_the_acl_prefix_is_the_limiters_own():
    import inspect

    from noctornal_api.ratelimit import RateLimiter
    default = inspect.signature(RateLimiter).parameters["key_prefix"].default
    assert limiter_key_prefix() == f"{default}:" == "rl:"
    assert readiness._limiter_prefix() == limiter_key_prefix().encode()


def test_the_commands_cover_what_the_script_calls():
    """ACL binds a script's own calls too: a command the Lua sends that the
    user may not run fails every limit at its first request."""
    called = {c.lower() for c in re.findall(r"redis\.call\('(\w+)'", _GCRA_LUA)}
    assert called == {"time", "get", "set"}
    assert called <= set(LIMITER_ACL_COMMANDS)
    # redis-py's Script: EVALSHA, then SCRIPT LOAD on NOSCRIPT. Never EVAL.
    assert {"evalsha", "script|load"} <= set(LIMITER_ACL_COMMANDS)
    assert "eval" not in LIMITER_ACL_COMMANDS
    # Nothing that writes server state, reads config or walks keys blocking.
    for refused in ("config|get", "config|set", "flushall", "flushdb", "keys",
                    "acl|setuser", "acl|save", "debug", "shutdown"):
        assert refused not in LIMITER_ACL_COMMANDS, refused
    assert not any(c.startswith("@") for c in LIMITER_ACL_COMMANDS)


def test_the_limiter_sends_no_client_command_so_none_is_granted():
    """CLIENT SETINFO was granted only so redis-py's library naming did not
    write denials into ACL LOG; the client now sends none (review of
    2026-10-02). The real-Redis leg reads ACL LOG to hold it."""
    assert not any(c.startswith("client") for c in LIMITER_ACL_COMMANDS)
    backend = RedisBackend("redis://limiter.test:6379/0")
    kwargs = backend._redis.connection_pool.connection_kwargs
    if "driver_info" in kwargs:
        assert kwargs["driver_info"] is None
    else:
        assert kwargs["lib_name"] is None and kwargs["lib_version"] is None
    connection = backend._redis.connection_pool.make_connection()
    assert getattr(connection, "driver_info", None) is None
    assert getattr(connection, "lib_name", None) is None


# ---------------------------------------------------------------------------
# maxmemory_policy asks INFO first
# ---------------------------------------------------------------------------

class InfoRedis:
    def __init__(self, info=None, info_error=None, config=None):
        self._info, self._info_error, self._config = info, info_error, config
        self.config_calls = 0

    def info(self, section=None):
        assert section == "memory"
        if self._info_error:
            raise self._info_error
        return self._info

    def config_get(self, name):
        self.config_calls += 1
        if self._config is None:
            raise RuntimeError("NOPERM config|get")
        return {name: self._config}

    def register_script(self, lua):
        return lambda keys, args: [1, 0, 0, 0]


def test_the_policy_comes_from_info_and_config_is_never_asked():
    fake = InfoRedis(info={"maxmemory_policy": "noeviction", "used_memory": 1})
    assert RedisBackend("redis://unused", client=fake).maxmemory_policy() == "noeviction"
    assert fake.config_calls == 0


def test_a_bytes_info_answer_is_decoded():
    fake = InfoRedis(info={b"maxmemory_policy": b"allkeys-lru"})
    assert RedisBackend("redis://unused", client=fake).maxmemory_policy() == "allkeys-lru"


def test_config_is_the_fallback_when_info_says_nothing():
    fake = InfoRedis(info_error=RuntimeError("NOPERM info"), config="volatile-ttl")
    assert RedisBackend("redis://unused", client=fake).maxmemory_policy() == "volatile-ttl"
    assert fake.config_calls == 1
    assert RedisBackend("redis://unused", client=InfoRedis(info={})).maxmemory_policy() is None


# ---------------------------------------------------------------------------
# Parsing ACL GETUSER
# ---------------------------------------------------------------------------

_CONFINED_RESP3 = {
    b"flags": [b"on", b"sanitize-payload"],
    b"passwords": [b"913ee7cf" * 8],
    b"commands": ("-@all " + " ".join(f"+{c}" for c in LIMITER_ACL_COMMANDS)).encode(),
    b"keys": b"~rl:*", b"channels": b"", b"selectors": []}
_OFF_RESP3 = {b"flags": [b"off", b"sanitize-payload"], b"passwords": [],
              b"commands": b"-@all", b"keys": b"", b"channels": b"", b"selectors": []}


def test_a_resp3_map_and_a_resp2_list_read_the_same():
    flat = [x for kv in _CONFINED_RESP3.items() for x in kv]
    assert readiness._acl_user(_CONFINED_RESP3) == readiness._acl_user(flat)
    user = readiness._acl_user(_CONFINED_RESP3)
    assert user.enabled and not user.nopass
    assert user.keys == ("rl:*",) and user.channels == ()
    assert set(user.granted) == set(LIMITER_ACL_COMMANDS)


def test_redis_6_shapes_are_read():
    """6.x: keys as a list of bare patterns and allkeys/allcommands as flags."""
    user = readiness._acl_user([b"flags", [b"on", b"allkeys", b"allcommands", b"nopass"],
                                b"passwords", [], b"commands", b"+@all",
                                b"keys", [], b"channels", [b"*"]])
    assert user.keys == ("*",) and user.nopass and "@all" in user.granted
    assert readiness._acl_user([b"flags", [b"on"], b"passwords", [], b"commands",
                                b"-@all +get", b"keys", [b"rl:*"]]).keys == ("rl:*",)


def test_read_and_write_key_marks_are_taken_off():
    user = readiness._acl_user({b"flags": [b"on"], b"commands": b"-@all",
                                b"keys": b"%R~rl:* %RW~cache:*", b"channels": b"&*"})
    assert user.keys == ("rl:*", "cache:*") and user.channels == ("*",)


def test_a_missing_user_is_none_and_a_strange_reply_is_refused():
    assert readiness._acl_user(None) is None
    with pytest.raises(ValueError):
        readiness._acl_user(b"OK")


# ---------------------------------------------------------------------------
# The readiness row
# ---------------------------------------------------------------------------

class AclRedis:
    """A limiter's Redis whose ACL is whatever the test says, and whose
    census finds only meters. Any command beyond those fails the test."""

    def __init__(self, *, whoami=LIMITER_ACL_USER, default=_OFF_RESP3, own=_CONFINED_RESP3,
                 acl_error=None):
        self._whoami, self._default, self._own = whoami, default, own
        self._acl_error = acl_error
        self.connection_pool = type("Pool", (), {"connection_kwargs": {"db": 0}})()

    def __getattr__(self, name):
        raise AssertionError(f"the row sent {name!r}")

    def ping(self):
        return True

    def register_script(self, lua):
        return lambda keys, args: [1, 0, 0, 0]

    def close(self):
        pass

    def dbsize(self):
        return 1

    def scan(self, cursor=0, count=None, **kwargs):
        return 0, [b"rl:login.ip:ip:203.0.113.9"]

    def info(self, section=None):
        return {"db0": {"keys": 1, "expires": 1}}

    def execute_command(self, *args):
        if self._acl_error is not None:
            raise self._acl_error
        if args[:2] == ("ACL", "WHOAMI"):
            return self._whoami.encode()
        if args[:2] == ("ACL", "GETUSER"):
            return self._default if args[2] == "default" else self._own
        raise AssertionError(f"the row sent {args!r}")


@pytest.fixture
def served(monkeypatch):
    import redis

    monkeypatch.setenv("REDIS_URL", f"redis://{LIMITER_ACL_USER}:{PASSWORD}@limiter.test:6379/0")

    def serve(fake, *, production=True):
        if production:
            monkeypatch.setenv("NOCTORNAL_ENV", "production")
        else:
            monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
        monkeypatch.setattr(redis.Redis, "from_url", classmethod(lambda cls, url, **kw: fake))
        return readiness._redis_limiter_isolated(None)
    return serve


def _clean(check):
    text = check.evidence + check.action
    assert PASSWORD not in text, "the Redis password reached the row"
    assert "913ee7cf" not in text, "a password hash reached the row"
    assert "203.0.113.9" not in text


def test_a_confined_limiter_passes_and_says_what_it_read(served):
    check = served(AclRedis())
    assert check.ok is True, check
    assert (f"lets the limiter's user {LIMITER_ACL_USER} read and write only keys "
            f"under rl: and run only the {len(LIMITER_ACL_COMMANDS)} commands it sends, "
            f"and the default user is disabled") in check.evidence, check.evidence
    # And what it does not confine, which "confined to rl:" had hidden
    # (review of 2026-10-02).
    assert ("can still list every key name in its database, read INFO and read "
            "any user's ACL rules") in check.evidence
    assert "would show only in the key census" in check.evidence
    _clean(check)


def _fails(check, *needles):
    assert check.ok is False, check
    assert check.evidence.startswith("Redis at "), check.evidence
    for needle in needles:
        assert needle in check.evidence, (needle, check.evidence)
    assert LIMITER_ACL_USER in check.action and "--production-secrets" in check.action
    _clean(check)


def test_production_fails_a_limiter_signed_in_as_default(served):
    open_default = {**_OFF_RESP3, b"flags": [b"on", b"nopass"], b"commands": b"+@all",
                    b"keys": b"~*", b"channels": b"&*"}
    _fails(served(AclRedis(whoami="default", default=open_default, own=open_default)),
           "signs in as the default user",
           "enabled and asks for no password")


def test_production_fails_an_open_default_beside_a_confined_limiter(served):
    open_default = {**_OFF_RESP3, b"flags": [b"on", b"nopass"]}
    _fails(served(AclRedis(default=open_default)),
           "every client that reaches this Redis is signed in as it")


def test_production_fails_a_default_user_behind_a_password(served):
    guarded = {**_OFF_RESP3, b"flags": [b"on"], b"passwords": [b"aa" * 32]}
    _fails(served(AclRedis(default=guarded)), "the default user is enabled, so whoever")


@pytest.mark.parametrize("own, needle", [
    ({**_CONFINED_RESP3, b"commands": _CONFINED_RESP3[b"commands"] + b" +flushall +config|get"},
     "may run config|get, flushall"),
    ({**_CONFINED_RESP3, b"commands": b"+@all"}, "may run @all"),
    ({**_CONFINED_RESP3, b"commands": b"-@all +@read +get"}, "may run @read"),
    ({**_CONFINED_RESP3, b"keys": b"~rl:* ~cache:*"}, "may touch 1 key pattern outside rl:"),
    ({**_CONFINED_RESP3, b"keys": b"~*"}, "outside rl:"),
    ({**_CONFINED_RESP3, b"keys": b"~r*"}, "outside rl:"),
    ({**_CONFINED_RESP3, b"keys": b""}, "may touch no key"),
    ({**_CONFINED_RESP3, b"channels": b"&*"}, "pub/sub channels"),
    ({**_CONFINED_RESP3, b"selectors": [{b"commands": b"+@all"}]}, "1 selector granting more"),
])
def test_production_fails_a_limiter_the_acl_does_not_confine(served, own, needle):
    _fails(served(AclRedis(own=own)), needle)


def test_production_fails_closed_on_a_user_with_no_rules_to_read(served):
    _fails(served(AclRedis(own=None)), "has no rules for its user noctornal_limiter")


def test_production_fails_closed_when_the_acl_cannot_be_read(served):
    refused = RuntimeError("User noctornal_limiter has no permissions to run the "
                           "'acl|getuser' command")
    _fails(served(AclRedis(acl_error=refused)), "its ACL could not be read",
           "nothing shows that the server confines it")


def test_a_development_redis_still_passes_and_says_production_would_not(served):
    open_default = {**_OFF_RESP3, b"flags": [b"on", b"nopass"], b"commands": b"+@all",
                    b"keys": b"~*", b"channels": b"&*"}
    check = served(AclRedis(whoami="default", default=open_default, own=open_default),
                   production=False)
    assert check.ok is True, check
    assert "the census alone decides this row" in check.evidence
    assert "signs in as the default user" in check.evidence
    assert "development stack's shape" in check.evidence
    _clean(check)


def test_a_production_failure_comes_before_the_census(served):
    """A Redis the ACL does not confine fails on that, not on a census the
    operator would fix second."""
    fake = AclRedis(whoami="default")
    fake.scan = None  # the census would raise on this
    _fails(served(fake), "signs in as the default user")


# ---------------------------------------------------------------------------
# Against a Redis started with the compose file's own start script
# ---------------------------------------------------------------------------

ACL_URL = os.environ.get("NOCTORNAL_TEST_ACL_REDIS_URL", "")
TENANT_URL = os.environ.get("NOCTORNAL_TEST_ACL_REDIS_TENANT_URL", "")
CI = ROOT / ".github" / "workflows" / "ci.yml"


def _ci_step(text: str, name: str) -> str:
    start = text.index(f"      - name: {name}\n")
    following = text.find("\n      - ", start + 1)
    return text[start:following if following > 0 else len(text)]


def test_ci_starts_the_acl_redis_and_names_both_urls(redis_service):
    """The leg below skips without its two variables, and CI's "No tests
    were skipped" gate then fails the build (review of 2026-10-02); set
    without a server, it fails instead. So the workflow starts one from
    the compose file's own start script, on both legs and before the Tests
    step, and points both variables at it."""
    text = CI.read_text(encoding="utf-8")
    env = text[text.index("\nenv:\n"):text.index("\njobs:\n")]
    urls = dict(re.findall(r"^  (NOCTORNAL_TEST_ACL_REDIS_\w*URL): (\S+)$", env, re.M))
    assert set(urls) == {"NOCTORNAL_TEST_ACL_REDIS_URL",
                         "NOCTORNAL_TEST_ACL_REDIS_TENANT_URL"}, urls
    limiter = urlsplit(urls["NOCTORNAL_TEST_ACL_REDIS_URL"])
    tenant = urlsplit(urls["NOCTORNAL_TEST_ACL_REDIS_TENANT_URL"])
    assert limiter.username == LIMITER_ACL_USER and tenant.username == TENANT_USER
    assert (limiter.hostname, limiter.port) == (tenant.hostname, tenant.port) == \
        ("localhost", limiter.port)
    step = _ci_step(text, "Start the ACL Redis")
    assert text.index("- name: Start the ACL Redis\n") < text.index("- name: Tests\n")
    assert "\n        if:" not in step, "both legs, from one definition"
    assert "python apps/api/tests/acl_redis_support.py --tenant" in step
    assert f" {redis_service['image']} " in step, "the compose file's image"
    assert f"127.0.0.1:{limiter.port}:6379" in step
    # Inside the container REDIS_URL names host `redis`, so the start
    # check takes its strict branch, the one production runs.
    assert f"REDIS_URL=redis://{LIMITER_ACL_USER}:{limiter.password}@redis:6379/0" in step
    assert re.search(r"REDIS_PASSWORD=(\S+)", step).group(1) == limiter.password
    assert re.search(r"ACL_TENANT_PASSWORD=(\S+)", step).group(1) == tenant.password


#: Every skip the files of the 2026-10 secrets and Redis work may carry, each
#: with what makes it false on CI's runner. A skip is a line in the first
#: leg's summary, and "No tests were skipped" fails the build for it (g32
#: verify of 2026-10-03: a skipif on Windows PowerShell did, on the Linux
#: runner, under a count the fixer took on Windows). A new skip has to be
#: added here with its reason, which is the moment to ask whether CI has it.
CI_SATISFIES = {
    "no POSIX sh on this machine": "ubuntu-latest has /bin/sh",
    "no bash on this machine": "ubuntu-latest has bash",
    "needs POSIX permissions and a user that is not root":
        "the runner is a Linux user that is not root, and the job has no container",
    "NOCTORNAL_TEST_ACL_REDIS_URL not set; the ACL Redis leg is gated":
        "ci.yml's env, with the Start the ACL Redis step behind it",
    "a second user on the ACL Redis is not configured":
        "ci.yml's env names the tenant too",
    "REDIS_URL not set; the Redis leg is gated": "ci.yml's env, and the redis service",
    "DATABASE_URL not set": "ci.yml's env, and the postgres service",
}
SKIP_SCANNED = (
    "acl_redis_support.py", "test_job_environment_refusals.py",
    "test_owner_credential_separation.py", "test_production_secrets_script.py",
    "test_redis_limiter_acl.py", "test_readiness_redis_isolation.py",
    "test_lookup_drain_pg.py",
)


def _skip_reasons(path: Path) -> list[str]:
    import ast
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("skipif", "skip", "importorskip")):
            continue
        if node.func.attr == "importorskip":
            found.append(f"{path.name}: importorskip {ast.unparse(node.args[0])}")
            continue
        reason = next((k.value for k in node.keywords if k.arg == "reason"), None)
        if reason is None and node.func.attr == "skip" and node.args:
            reason = node.args[0]
        assert isinstance(reason, ast.Constant) and isinstance(reason.value, str), \
            f"{path.name}:{node.lineno}: give the skip one string literal as its reason"
        found.append(reason.value)
    return found


def test_every_skip_in_these_files_is_one_the_ci_runner_satisfies():
    """The gate counts a skip on Linux whatever platform the fixer was on.
    So every skip these files carry is listed with what makes it false in
    CI, and CI is held to provide each: the Linux runner and no container
    (so no root), the Postgres and Redis services and their URLs. The ACL
    URLs and their server are held by the test above."""
    found = [r for name in SKIP_SCANNED for r in _skip_reasons(Path(__file__).parent / name)]
    assert not [r for r in found if r not in CI_SATISFIES], \
        "a skip CI may satisfy is not listed (or one that no Linux runner can satisfy): " \
        f"{sorted(set(found) - set(CI_SATISFIES))}"
    assert set(found) == set(CI_SATISFIES), "a listed skip is gone: drop it from the table"
    text = CI.read_text(encoding="utf-8")
    env = text[text.index("\nenv:\n"):text.index("\njobs:\n")]
    for variable in ("DATABASE_URL", "REDIS_URL", "NOCTORNAL_TEST_ACL_REDIS_URL",
                     "NOCTORNAL_TEST_ACL_REDIS_TENANT_URL"):
        assert re.search(rf"^  {variable}: \S+$", env, re.M), variable
    job = text[text.index("\n  test:\n"):]
    assert "\n    runs-on: ubuntu-latest\n" in job
    assert "\n    container:" not in job
    assert "\n      postgres:\n" in job and "\n      redis:\n" in job


def test_the_rendered_start_script_is_the_compose_files_own(redis_service):
    """What CI runs is the compose script with `$$` written back, and with
    --tenant one printf line more, before the server starts."""
    plain = start_script()
    assert plain == _script(redis_service).replace("$$", "$")
    with_tenant = start_script(tenant=True)
    extra = [line for line in with_tenant.splitlines() if line not in plain.splitlines()]
    assert len(extra) == 1 and extra[0].strip().startswith(f"printf 'user {TENANT_USER} on >%s")
    assert with_tenant.index(extra[0]) < with_tenant.index("exec redis-server")
needs_acl_redis = pytest.mark.skipif(
    not ACL_URL, reason="NOCTORNAL_TEST_ACL_REDIS_URL not set; the ACL Redis leg is gated")


def _client(url):
    import redis
    return redis.Redis.from_url(url, socket_connect_timeout=1, socket_timeout=1)


@needs_acl_redis
def test_the_limiter_meters_and_claims_under_its_acl():
    backend = RedisBackend(ACL_URL)
    key = f"rl:acl-proof:{uuid4().hex}"
    try:
        first = backend.measure(key, 1_000_000, 2_000_000)
        assert first.allowed
        assert backend.peek(key, 1_000_000, 2_000_000).allowed in (True, False)
        assert backend.claim_once(f"rl:audit:acl-proof:{uuid4().hex}", 5) is True
        assert backend.ping() is True
        assert backend.maxmemory_policy() == "noeviction"
        assert backend._redis.script_load("return 1")  # SCRIPT LOAD, for NOSCRIPT
    finally:
        backend.close()


@needs_acl_redis
@pytest.mark.parametrize("command", [
    ("GET", "cache:another-users-key"),
    ("SET", "cache:another-users-key", "1"),
    ("DEL", "rl:not-even-mine-to-delete"),
    ("FLUSHALL",),
    ("FLUSHDB",),
    ("CONFIG", "GET", "maxmemory-policy"),
    ("CONFIG", "SET", "maxmemory-policy", "allkeys-lru"),
    ("KEYS", "*"),
    ("EVAL", "return 1", "0"),
    ("ACL", "SETUSER", "default", "on", "nopass"),
    ("PUBLISH", "chan", "x"),
])
def test_the_acl_refuses_what_the_limiter_does_not_send(command):
    import redis
    client = _client(ACL_URL)
    try:
        with pytest.raises(redis.exceptions.NoPermissionError):
            client.execute_command(*command)
    finally:
        client.close()


@needs_acl_redis
def test_the_script_cannot_reach_a_key_outside_the_prefix():
    """The ACL binds the keys a script declares, so the limiter's own Lua
    pointed at another key is refused too."""
    import redis
    backend = RedisBackend(ACL_URL)
    try:
        with pytest.raises(redis.exceptions.NoPermissionError):
            backend._script(keys=["cache:another-users-key"], args=[1, 1, 1])
    finally:
        backend.close()


@needs_acl_redis
def test_the_default_user_is_off():
    import redis
    parts = urlsplit(ACL_URL)
    anonymous = urlunsplit((parts.scheme, f"{parts.hostname}:{parts.port}", parts.path, "", ""))
    client = _client(anonymous)
    try:
        with pytest.raises(redis.exceptions.AuthenticationError):
            client.ping()
    finally:
        client.close()
    as_default = urlunsplit((parts.scheme, f"default:{parts.password}@{parts.hostname}:{parts.port}",
                            parts.path, "", ""))
    client = _client(as_default)
    try:
        with pytest.raises(redis.exceptions.AuthenticationError):
            client.ping()
    finally:
        client.close()


@needs_acl_redis
def test_the_row_passes_on_the_real_acl_in_production(monkeypatch):
    monkeypatch.setenv("REDIS_URL", ACL_URL)
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    check = readiness._redis_limiter_isolated(None)
    if TENANT_URL:
        # The tenant leg below may have left a key; only the ACL half is ours here.
        assert "its ACL does not confine" not in check.evidence, check.evidence
        return
    assert check.ok is True, check
    assert f"confines the limiter's user {LIMITER_ACL_USER}" in check.evidence
    assert urlsplit(ACL_URL).password not in check.evidence + check.action


@pytest.mark.skipif(not (ACL_URL and TENANT_URL),
                    reason="a second user on the ACL Redis is not configured")
def test_the_limiter_and_its_rows_leave_acl_log_empty(monkeypatch):
    """Nothing the limiter or its two readiness rows send is refused by
    the ACL, so a denial in ACL LOG is always somebody else's attempt. It
    is what took CLIENT SETINFO off the grants (review of 2026-10-02): an
    ACL without it and a client still sending it fail here. The tenant
    reads the log, which the limiter's user may not."""
    tenant = _client(TENANT_URL)
    try:
        tenant.execute_command("ACL", "LOG", "RESET")
        backend = RedisBackend(ACL_URL)
        try:
            key = f"rl:acl-log:{uuid4().hex}"
            backend.measure(key, 1_000_000, 2_000_000)
            backend.peek(key, 1_000_000, 2_000_000)
            backend.claim_once(f"rl:audit:acl-log:{uuid4().hex}", 5)
            assert backend.ping() is True
            assert backend.maxmemory_policy() == "noeviction"
        finally:
            backend.close()
        monkeypatch.setenv("REDIS_URL", ACL_URL)
        monkeypatch.setenv("NOCTORNAL_ENV", "production")
        readiness._redis_limiter_isolated(None)
        readiness._redis_limiter_store(None)
        assert tenant.execute_command("ACL", "LOG") == []
    finally:
        tenant.close()


@pytest.mark.skipif(not (ACL_URL and TENANT_URL),
                    reason="a second user on the ACL Redis is not configured")
def test_another_users_key_is_refused_to_the_limiter_and_counted(monkeypatch):
    """A user the compose file does not define (the test's server adds one)
    writes a key; the limiter can neither read nor delete it, and the census
    still reports it by count."""
    import redis
    tenant = _client(TENANT_URL)
    name = f"cache:acl-proof:{uuid4().hex}"
    tenant.set(name, "never-read", px=30_000)
    limiter = _client(ACL_URL)
    try:
        for command in (("GET", name), ("DEL", name), ("TYPE", name)):
            with pytest.raises(redis.exceptions.NoPermissionError):
                limiter.execute_command(*command)
        monkeypatch.setenv("REDIS_URL", ACL_URL)
        monkeypatch.setenv("NOCTORNAL_ENV", "production")
        check = readiness._redis_limiter_isolated(None)
        assert check.ok is False and "SHARED" in check.evidence, check
        assert name not in check.evidence
    finally:
        tenant.delete(name)
        tenant.close()
        limiter.close()
